import argparse
import csv
import logging
import os
import sys
import zipfile
from datetime import datetime

import pytz
import urllib3
import wget
import magic
import yaml
from pymisp import ExpandedPyMISP, MISPOrganisation, MISPSighting, MISPAttribute, MISPEvent, MISPObject


class AbuseChDownloader:
    def __init__(self, logger, download_dir):
        self.logger = logger
        self.download_dir = download_dir

    def download_feed(self, url):
        out = self.get_output_file()
        self.logger.info("Download " + url)
        try:
            wget.download(url, out=out)
        except Exception as e:
            self.logger.error("Error while Downloading " + url)
            self.logger.error(e)
            return None
        self.logger.info("Saved file " + out)
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(out)
        if 'zip' in file_type:
            self.logger.info("Archive detected, try to extract")
            out = self.unpack(out)
        self.logger.info("IOC File: " + out)
        return out

    def get_output_file(self):
        prefix = 1
        out = os.path.join(self.download_dir, "iocs." + str(prefix))
        while os.path.exists(out) and os.path.isfile(out):
            prefix = prefix + 1
            out = os.path.join(self.download_dir, "iocs." + str(prefix))
        return out

    def unpack(self, file):
        zf = zipfile.ZipFile(file)
        if len(zf.namelist()) > 1:
            self.logger.error("multiple files contained in zip archive")
            exit(1)
        out = os.path.join(self.download_dir, zf.namelist()[0])
        zf.extractall(path=self.download_dir)
        return out


class MispHandler:
    def __init__(self, config, logger):
        self.logger = logger
        MISP_KEY = config['MISP_KEY']
        MISP_URL = config['MISP_URL']
        MISP_VERIFYCERT = config['MISP_VERIFYCERT']
        self.config = config
        self.misp = ExpandedPyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
        self.orgc = MISPOrganisation()
        self.orgc.name = config['MISP_ORG_NAME']
        self.orgc.id = config['MISP_ORG_ID']
        self.orgc.uuid = config['MISP_ORG_UUID']
        self.tags = config['tags']
        self.galaxy_synonyms = {}
        self.enabled_clusters = self.config['galaxies']
        self.galaxy_tags = {}
        self._init_galaxies()

    def get_event_id(self, event):
        try:
            return event['Event']['id']
        except KeyError:
            return event.id
        except TypeError:
            return event.id

    def get_attributes(self, event):
        try:
            attributes = event['Event']['Attribute']
        except KeyError:
            attributes = event.attributes
        return attributes

    def add_sigthing(self, id):
        sighting = MISPSighting()
        self.misp.add_sighting(sighting, id)

    def get_event(self, malware_type, feed_tag):
        malware_tag = "malware:" + malware_type.lower()
        res = self.misp.search(tags=[feed_tag], controller='events', pythonify=True)
        for event in res:
            for tag in event.tags:
                if tag['name'].lower() == malware_tag.lower():
                    return event
        return None

    def _init_galaxies(self):
        i = 1
        cont = True
        for cluster in self.enabled_clusters:
            self.galaxy_tags[cluster] = []

        while cont:
            g = self.misp.get_galaxy(i)
            try:
                galaxy_cluster = g['Galaxy']['name']
            except KeyError:
                cont = False
                continue
            if galaxy_cluster.lower() in self.enabled_clusters:
                elements = g['GalaxyCluster']
                for element in elements:
                    self.galaxy_tags[galaxy_cluster.lower()].append(element['tag_name'])

                    for inner_element in element['GalaxyElement']:
                        if inner_element['key'] == 'synonyms':
                            if not element['tag_name'] in self.galaxy_synonyms:
                                self.galaxy_synonyms[element['tag_name']] = []
                            self.galaxy_synonyms[element['tag_name']].append(inner_element['value'])
            i = i + 1

    def get_galaxies(self, malware_tag):
        res = []
        for cluster in self.enabled_clusters:
            for galaxy_tag in self.galaxy_tags[cluster]:
                malware = malware_tag.split(':')[1].lower().replace(" ", "")
                galaxy_value = galaxy_tag.split('"')[1].lower().replace(" ", "")
                if malware == galaxy_value:
                    res.append(galaxy_tag)
                    break
                else:
                    if galaxy_tag in self.galaxy_synonyms:
                        for synonym in self.galaxy_synonyms[galaxy_tag]:
                            galaxy_value = synonym.lower().replace(" ", "")
                            if malware == galaxy_value:
                                res.append(galaxy_tag)
                                break
        return res

    def get_file_taxonomy(self, ft):
        if ft == 'exe':
            return 'file-type:type="peexe"'
        elif ft == 'dll':
            return 'file-type:type="pedll"'
        elif ft == 'zip':
            return 'file-type:type="zip"'
        elif ft == 'apk':
            return 'file-type:type="android"'
        elif ft == 'rar':
            return 'file-type:type="rar"'
        elif ft == 'xls':
            return 'file-type:type="xls"'
        elif ft == 'xlsx':
            return 'file-type:type="xlsx"'
        elif ft == 'doc':
            return 'file-type:type="doc"'
        elif ft == 'docx':
            return 'file-type:type="docx"'
        elif ft == '7z' or ft == '7zip':
            return 'file-type:type="7zip"'
        elif ft == 'gz' or ft == 'gzip':
            return 'file-type:type="gzip"'

        file_types = self.misp.get_taxonomy(52)['entries']

        for file_type in file_types:
            if ft == file_type['tag'].split('"')[1].strip():
                return file_type['tag']

        print("Unknown Filetype: " + ft)
        return ''

    def new_misp_event(self, malware_type, feed_tag, event_info, additional_tags=[],
                       info_cred='admirality-scale:information-credibility="2"'):
        malware_tag = "malware:" + malware_type.lower()
        misp_event_obj = MISPEvent()
        misp_event_obj.info = event_info
        misp_event_obj.add_tag(feed_tag)
        misp_event_obj.add_tag(info_cred)
        if len(malware_tag) > 0:
            misp_event_obj.add_tag(malware_tag.lower())
        for tag in self.config['tags']:
            misp_event_obj.add_tag(tag)
        for tag in additional_tags:
            misp_event_obj.add_tag(tag)
        misp_event_obj.orgc = self.orgc

        galaxies = self.get_galaxies(malware_tag)
        for galaxy in galaxies:
            misp_event_obj.add_tag(galaxy)
        misp_event = self.misp.add_event(misp_event_obj)
        return misp_event


class AbuseChImporter:
    def __init__(self, logger, config):
        self.config = config
        self.mh = MispHandler(config, logger)
        self.misp = self.mh.misp
        self.logger = logger
        self.misp_events = {}
        download_dir = config['download_dir']
        self.dl = AbuseChDownloader(logger, download_dir)
        self.infile = None


class BazaarImporter(AbuseChImporter):
    def __init__(self, logger, config, full_import=False):
        self.error = False
        if full_import:
            url = 'https://bazaar.abuse.ch/export/csv/full/'
        else:
            url = 'https://bazaar.abuse.ch/export/csv/recent/'
        super(BazaarImporter, self).__init__(logger, config)
        self.infile = self.dl.download_feed(url)
        if self.infile is None:
            self.logger.error("Download Error")
            self.error = True
        self.feed_tag = 'feed:abusech="malware-bazaar"'

    def import_data(self):
        csvfile = open(self.infile, "r")

        for line in csvfile:
            row = line.split('", "')
            if row[0].startswith("#") or len(row) < 12:
                continue

            malware_type = row[8].strip().strip('"')
            object = self.map_object(row)
            if object is None:
                continue
            if malware_type in self.misp_events:
                event = self.misp_events[malware_type]
            else:
                event = self.mh.get_event(malware_type, self.feed_tag)
                if event is None:
                    event_info = "Malware Bazaar: " + malware_type
                    event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info)
                self.misp_events[malware_type] = event
            eventid = self.mh.get_event_id(event)

            self.misp.add_object(eventid, object)

        for malware_type in self.misp_events:
            self.misp.publish(self.mh.get_event_id(self.misp_events[malware_type]))

    def map_object(self, row):
        misp_object = MISPObject("file")
        misp_object.name = "file"
        misp_object.first_seen = datetime.strptime(row[0].strip().strip('"'), '%Y-%m-%d %H:%M:%S')
        ft = row[6].strip().strip("")
        file_type = "File Type Guess: " + ft
        sha256 = row[1].strip().strip('"')
        tax = self.mh.get_file_taxonomy(ft)
        link = "https://bazaar.abuse.ch/sample/" + sha256

        res = self.misp.search(controller='attributes', value=link)
        if len(res['Attribute']) > 0:
            return None
        misp_object.add_attribute("sha1", value=row[3].strip().strip('"'), type="sha1")
        misp_object.add_attribute("md5", value=row[2].strip().strip('"'), type="md5")
        misp_object.add_attribute("sha256", value=sha256, type="sha256")
        misp_object.add_attribute("filename", value=row[5].strip().strip('"'), type='filename')
        misp_object.add_attribute("ssdeep", value=row[12].strip().strip('"'), type='ssdeep')
        misp_object.add_attribute("tlsh", value=row[13].strip().strip('"'), type='tlsh')
        mime_type = "Mime-Type: " + row[7].strip().strip('"')
        misp_object.add_attribute("mimetype", value=mime_type, type='mime-type')
        misp_object.add_attribute("link", value=link, type='link')
        vt = "VT detection Rate: " + row[10].strip().strip('"') + "%"
        if vt != 'n/a%':
            misp_object.add_attribute("text", value=vt, type='text')
        imphash = row[11].strip().strip('"')
        if imphash != 'n/a':
            misp_object.add_attribute("imphash", value=imphash, type='imphash')
        if tax == '':
            misp_object.add_attribute("text", value=file_type, type="text")
        else:
            for attr in misp_object.attributes:
                if attr.to_ids and not attr.disable_correlation:
                    attr.add_tag(tax)
        return misp_object


class SSLBLImporter(AbuseChImporter):
    def __init__(self, logger, config):
        self.error = False
        url = 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv'
        super(SSLBLImporter, self).__init__(logger, config)
        self.infile = self.dl.download_feed(url)
        if self.infile is None:
            self.logger.error("Download Error")
            self.error = True
        self.feed_tag = 'feed:abusech="SSL-Certificate-Blacklist"'

    def import_data(self):
        csvfile = open(self.infile, "r")
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            exists = False
            if row[0].startswith("#"):
                continue
            malware_type = row[2].split(' ')[0]
            if malware_type in self.misp_events:
                event = self.misp_events[malware_type]
            else:
                event = self.mh.get_event(malware_type, self.feed_tag)
                if event is None:
                    event_info = "C2 SSL Certificates: " + malware_type
                    tags = []
                    tags.append('common-taxonomy:malware="command-and-control"')
                    tags.append('kill-chain:Command and Control')
                    event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info, additional_tags=tags)
                self.misp_events[malware_type] = event

            attributes = self.mh.get_attributes(event)
            for attribute in attributes:
                if attribute.value == row[1].strip().strip('"'):
                    exists = True
                    break
            if exists:
                continue
            eventid = self.mh.get_event_id(event)
            new_attribute = self.map_attribute(row)
            self.misp.add_attribute(eventid, new_attribute)

        for malware_type in self.misp_events:
            self.misp.publish(self.mh.get_event_id(self.misp_events[malware_type]))

    def map_attribute(self, row):
        misp_attribute = MISPAttribute()
        fs = datetime.strptime(row[0].strip().strip('"'), '%Y-%m-%d %H:%M:%S')
        misp_attribute.first_seen = fs
        misp_attribute.last_seen = fs
        value = row[1].strip().strip('"')
        misp_attribute.type = "x509-fingerprint-sha1"
        misp_attribute.comment = 'https://sslbl.abuse.ch/ssl-certificates/sha1/' + value

        misp_attribute.value = value
        return misp_attribute


class SSLBLIPImporter(AbuseChImporter):
    def __init__(self, logger, config, import_agressive=False):
        self.error = False
        self.import_agressive = import_agressive
        if import_agressive:
            url = 'https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv'
            self.feed_tag = 'feed:abusech="SSL-Cert-BL-IPs-Aggressive"'
        else:
            url = 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv'
            self.feed_tag = 'feed:abusech="SSL-Cert-BL-IPs"'
        super(SSLBLIPImporter, self).__init__(logger, config)
        self.infile = self.dl.download_feed(url)
        if self.infile is None:
            self.logger.error("Download Error")
            self.error = True

    def import_data(self):
        csvfile = open(self.infile, "r")
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            exists = False
            if row[0].startswith("#"):
                continue
            malware_type = 'n/a'
            if malware_type in self.misp_events:
                event = self.misp_events[malware_type]
            else:
                event = self.mh.get_event(malware_type, self.feed_tag)
                if event is None:
                    event_info = "C2 IPs identified by SSL Certificates"
                    tags = []
                    tags.append('common-taxonomy:malware="command-and-control"')
                    tags.append('kill-chain:Command and Control')
                    event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info, additional_tags=tags)
                self.misp_events[malware_type] = event

            attributes = self.mh.get_attributes(event)
            for attribute in attributes:
                if attribute.value == row[1].strip().strip('"') + "|" + row[2].strip().strip('"'):
                    exists = True
                    break
            if exists:
                continue
            eventid = self.mh.get_event_id(event)
            new_attribute = self.map_attribute(row)
            self.misp.add_attribute(eventid, new_attribute)

        for malware_type in self.misp_events:
            self.misp.publish(self.mh.get_event_id(self.misp_events[malware_type]))

    def map_attribute(self, row):
        misp_attribute = MISPAttribute()
        fs = datetime.strptime(row[0].strip().strip('"'), '%Y-%m-%d %H:%M:%S')
        misp_attribute.first_seen = fs
        misp_attribute.last_seen = fs
        value = row[1].strip().strip('"') + "|" + row[2].strip().strip('"')
        misp_attribute.type = "ip-dst|port"

        misp_attribute.value = value
        return misp_attribute


class FeodoImporter(AbuseChImporter):
    def __init__(self, logger, config, import_agressive=False):
        self.error = False
        self.import_agressive = import_agressive
        if import_agressive:
            url = 'https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv'
        else:
            url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv'
        super(FeodoImporter, self).__init__(logger, config)
        self.infile = self.dl.download_feed(url)
        if self.infile is None:
            self.logger.error("Download Error")
            self.error = True

    def import_data(self):
        if self.import_agressive:
            self.feed_tag = 'feed:abusech="Feodo-tracker-agressive"'
            type_index = 3
        else:
            self.feed_tag = 'feed:abusech="Feodo-tracker"'
            type_index = 4

        csvfile = open(self.infile, "r")
        readCSV = csv.reader(csvfile, delimiter=',')

        for row in readCSV:
            malware_type = ''
            if row[0].startswith("#") or len(row) < type_index:
                continue
            try:
                malware_type = row[type_index].strip().strip('"')
            except IndexError as e:
                self.logger.error(e)
                # pdb.set_trace()
            if malware_type in self.misp_events:
                event = self.misp_events[malware_type]
            else:
                event = self.mh.get_event(malware_type, self.feed_tag)
                if event is None:
                    event_info = "Feodo Tracker: " + malware_type
                    tags = []
                    tags.append('common-taxonomy:malware="command-and-control"')
                    tags.append('kill-chain:Command and Control')
                    if self.import_agressive:
                        info_cred = 'admirality-scale:information-credibility="4"'
                    else:
                        info_cred = 'admirality-scale:information-credibility="2"'
                    event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info, additional_tags=tags,
                                                   info_cred=info_cred)
                self.misp_events[malware_type] = event
            new_attribute = self.map_attribute(row)
            eventid = self.mh.get_event_id(event)
            exitsts = False
            try:
                for attribute in event.attributes:
                    if attribute.value == new_attribute.value:
                        ls_string = row[3].strip().strip('"')
                        ls = datetime.strptime(ls_string, '%Y-%m-%d')

                        ls = ls.replace(tzinfo=pytz.UTC)

                        if ls > attribute.last_seen:
                            attribute.last_seen = ls
                            self.mh.add_sigthing(attribute.id)
                            self.misp.update_attribute(attribute, attribute.id)
                        exitsts = True
                    continue
            except:
                pass
            if exitsts == False:
                self.misp.add_attribute(eventid, new_attribute)

        for malware_type in self.misp_events:
            self.misp.publish(self.mh.get_event_id(self.misp_events[malware_type]))

    def map_attribute(self, row):
        misp_attribute = MISPAttribute()
        fs = datetime.strptime(row[0].strip().strip('"'), '%Y-%m-%d %H:%M:%S')
        misp_attribute.first_seen = fs
        try:
            ls_string = row[3].strip().strip('"')
            if ls_string != '':
                ls = datetime.strptime(ls_string, '%Y-%m-%d')

                if ls > fs:
                    misp_attribute.last_seen = ls
                else:
                    misp_attribute.last_seen = fs
        except ValueError:
            pass
        value = row[1].strip().strip('"') + "|" + row[2].strip().strip('"')
        misp_attribute.type = "ip-dst|port"
        misp_attribute.comment = 'https://feodotracker.abuse.ch/browse/host/' + row[1].strip().strip('"')

        misp_attribute.value = value
        return misp_attribute


class UrlHausImporter(AbuseChImporter):
    def __init__(self, logger, config, feed='online'):
        self.error = False
        self.feed = feed
        url = ''
        if feed == 'online':
            url = 'https://urlhaus.abuse.ch/downloads/csv_online/'
        elif feed == 'recent':
            url = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
        elif feed == 'full':
            url = 'https://urlhaus.abuse.ch/downloads/csv/'
        self.feed_tag = 'feed:abusech="URLHaus"'
        super(UrlHausImporter, self).__init__(logger, config)
        self.infile = self.dl.download_feed(url)
        if self.infile is None:
            self.logger.error("Download Error")
            self.error = True

    def import_data(self):
        csvfile = open(self.infile, "r")

        for line in csvfile:
            exists = False
            row = line.split('","')
            if row[0].startswith("#"):
                continue
            malware_info = self.get_malware_info(row)
            malware_type = malware_info['mt']
            if malware_type == '':
                malware_type = "n/a"
            ft = malware_info['ft']

            if malware_type in self.misp_events:
                event = self.misp_events[malware_type]
            else:
                event = self.mh.get_event(malware_type, self.feed_tag)
                if event is None:
                    event_info = "UrlHaus Malware URLs: " + malware_type
                    tags = []
                    info_cred = 'admirality-scale:information-credibility="2"'
                    event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info, additional_tags=tags,
                                                   info_cred=info_cred)
                self.misp_events[malware_type] = event
            attributes = self.mh.get_attributes(event)
            for attribute in attributes:
                if attribute.value == row[2].strip().strip('"'):
                    exists = True
                    if self.feed == 'online':
                        self.mh.add_sigthing(attribute.id)
                        attribute.last_seen = datetime.now()
                        self.misp.update_attribute(attribute, attribute.id)
                    break
            if exists:
                continue

            eventid = self.mh.get_event_id(event)
            attr = self.map_attribute(row)
            self.misp.add_attribute(eventid, attr)

        for malware_type in self.misp_events:
            self.misp.publish(self.mh.get_event_id(self.misp_events[malware_type]))

    def map_attribute(self, row):
        malware_info = self.get_malware_info(row)
        misp_attribute = MISPAttribute()
        value = row[2].strip().strip('"')
        fs = datetime.strptime(row[1].strip().strip('"'), '%Y-%m-%d %H:%M:%S')
        misp_attribute.first_seen = fs
        misp_attribute.last_seen = fs
        misp_attribute.type = "url"

        if row[4].strip().strip('"') == "malware_download":
            misp_attribute.add_tag('kill-chain:Delivery')
        if malware_info['ft'] is not None:
            misp_attribute.add_tag(malware_info['ft'])
        misp_attribute.value = value
        misp_attribute.comment = row[6].strip().strip('"')
        return misp_attribute

    def get_malware_info(self, row):
        malware_list = ['Heodo', 'CobaltStrike', 'Dridex', 'Emotet', 'Formbook', 'Nanocore', 'TA505', 'Qakbot', 'Qbot',
                        'Coinminer', 'Loki', 'AgentTesla', 'Trickbot', 'Zloader', 'Remcosrat', 'Gozi', 'Mozi', 'Mirai',
                        'IcedID', 'Valak', 'SystemBC', 'njRat']
        file_type_list = ['dll', 'exe', 'elf', 'doc']
        tags = row[5].split(',')
        ft = None
        malware_tag = ''
        found = False

        for tag in tags:
            if tag in file_type_list:
                ft = self.mh.get_file_taxonomy(tag)
            for malware in malware_list:
                if tag.lower() == malware.lower():
                    found = True
                    malware_tag = malware
                    break
            if found:
                break
        return {'mt': malware_tag, 'ft': ft}


def init_logger(level):
    logger = logging.getLogger('abusech-to-misp')

    handler = logging.StreamHandler(sys.stdout)
    level = logging.getLevelName(level)
    handler.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def load_config(config_file, logger):
    try:
        with open(config_file) as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
    except Exception as e:
        logger.error("Error while loadig Config")
        logger.error(e)
    return config


if __name__ == '__main__':
    urllib3.disable_warnings()
    parser = argparse.ArgumentParser(description='Sync AbuseCH to MISP')
    parser.add_argument('-c', '--config', required=True, help='Config File')
    parser.add_argument('-l', '--loglevel', required=False, help='Set Log Level',
                        choices=['DEBUG', "INFO", "WARNING", "ERROR", 'CRITICAL'], default='Debug')

    args = parser.parse_args()
    logger = init_logger(args.loglevel)

    config = load_config(args.config, logger)

    if 'log_level' in config:
        logger.setLevel(logging.getLevelName(config['log_level']))

    bi = BazaarImporter(logger, config, full_import=False)
    if not bi.error:
        bi.import_data()
    fi = FeodoImporter(logger, config, import_agressive=True)
    if not fi.error:
        fi.import_data()
    si = SSLBLImporter(logger, config)
    if not si.error:
        si.import_data()
    si = SSLBLIPImporter(logger, config, import_agressive=True)
    if not si.error:
        si.import_data()
    ui = UrlHausImporter(logger, config, feed='full')  # Feeds: full, recent, online
    ui.import_data()
