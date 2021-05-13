"""DNS Authenticator for YandexCloud."""
import json
import logging

import zope.interface
from certbot import interfaces
import requests as req
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for YandexCloud

    This Authenticator uses the YandexCloud Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using YandexCloud for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="YandexCloud credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using the YandexCloud Remote REST API."

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "YandexCloud credentials INI file",
            {"token": "URL of the YandexCloud Remote API."},
        )

    def _perform(self, domain, validation_name, validation):
        self._get_yandexcloud_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_yandexcloud_client().del_txt_record(domain, validation_name, validation, self.ttl)

    def _get_yandexcloud_client(self):
        return _YandexCloudClient(self.credentials.conf("token"))


class _YandexCloudClient(object):
    """
    Encapsulates all communication with the ISPConfig Remote REST API.
    """

    def __init__(self, token):
        logger.debug("creating Yandex Cloud Client")
        self.token = token
        self.domains = self._get_account_domains()

    def _get_account_domains(self):
        domains = {}
        headers = {"Authorization": "Bearer %s" % self.token}
        r = req.get('https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds', headers=headers)
        if "\"message\"" in r.text:
            print("Api calling error: %s" % json.loads(r.text)["message"])

        for cloud in json.loads(r.text)["clouds"]:
            r = req.get(
                "https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders?cloudId=%s" % cloud["id"],
                headers=headers)
            if "\"message\"" in r.text:
                print("Api calling error: %s" % json.loads(r.text)["message"])
                break

            for folder in json.loads(r.text)["folders"]:
                r = req.get("https://dns.api.cloud.yandex.net/dns/v1/zones?folderId=%s" % folder["id"], headers=headers)
                if "\"message\"" in r.text:
                    print("Api calling error: %s" % json.loads(r.text)["message"])
                    break

                for zone in json.loads(r.text)["dnsZones"]:
                    domains[zone["zone"]] = zone["id"]
        return domains

    def _get_domain_id(self, domain):
        for name, zone in self.domains.items():
            if name == domain+".":
                return zone
        return None

    def _get_record_ttl(self, domain_id, record_name):
        headers = {"Authorization": "Bearer %s" % self.token}
        r = req.get("https://dns.api.cloud.yandex.net/dns/v1/zones/%s:getRecordSet?name=%s.&type=TXT" %
                    (domain_id, record_name), headers=headers)
        if "\"message\"" in r.text:
            print("Api calling error: %s" % json.loads(r.text)["message"])
            return None

        return json.loads(r.text)["ttl"]

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        current = self._get_domain_id(domain)
        if current is None:
            print("Domain not found")
            return

        headers = {"Authorization": "Bearer %s" % self.token}
        payload = json.dumps({
            "additions": [
                {
                    "name": record_name+".",
                    "type": "TXT",
                    "ttl": record_ttl,
                    "data": [record_content]
                }
            ]
        })
        r = req.post("https://dns.api.cloud.yandex.net/dns/v1/zones/%s:updateRecordSets" % current, headers=headers,
                     data=payload)
        if "\"message\"" in r.text:
            print("Api calling error: %s" % json.loads(r.text)["message"])

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        current = self._get_domain_id(domain)
        if current is None:
            print("Domain not found")

        headers = {"Authorization": "Bearer %s" % self.token}
        payload = json.dumps({
            "deletions": [
                {
                    "name": record_name+".",
                    "type": "TXT",
                    "ttl": record_ttl,
                    "data": [record_content]
                }
            ]
        })
        r = req.post("https://dns.api.cloud.yandex.net/dns/v1/zones/%s:updateRecordSets" % current, headers=headers,
                     data=payload)
        if "\"message\"" in r.text:
            print("Api calling error: %s" % json.loads(r.text)["message"])
