import argparse
import csv
import logging
import os
import pdb
import re
import sys
import zipfile
from datetime import datetime
from time import sleep

import pytz
import requests
import urllib3
import wget
import magic
import yaml
from pyfaup.faup import Faup
from pymisp import ExpandedPyMISP, MISPOrganisation, MISPSighting, MISPAttribute, MISPEvent, MISPObject, \
    PyMISPInvalidFormat


class AbuseChDownloader:
    def __init__(self, logger, download_dir, config):
        self.logger = logger
        self.download_dir = download_dir
        if config['HTTP_PROXY'] == 'None':
            self.http_proxy = None
        else:
            self.http_proxy = config['HTTP_PROXY']
        if config['HTTPS_PROXY'] == 'None':
            self.https_proxy = None
        else:
            self.https_proxy = config['HTTPS_PROXY']

    def download_feed(self, url):
        out = self.get_output_file()
        self.logger.info("Download " + url)
        try:
            if self.http_proxy is None and self.https_proxy is None:
                wget.download(url, out=out)
            else:
                r = requests.get(url, stream=True, proxies={'http': self.http_proxy, 'https': self.https_proxy})
                with open(out, 'wb') as f:
                    for chunk in r:
                        f.write(chunk)
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

    def add_object(self, evetid, misp_obj):
        try:
            self.misp.add_object(evetid, misp_obj)
        except Exception as e:
            self.logger.error("Error while adding an object. Wait a second and try again")
            sleep(1)
            try:
                self.misp.add_attribute(evetid, misp_obj)
            except Exception as e:
                self.logger.error("Second error for the object:")
                self.logger.error("Object: " + str(misp_obj))
                self.logger.error('Eventid:' + str(evetid))
                self.logger.error(e)
                self.logger.error("Ignoring this object")
        return int(self.misp.get_event(evetid, pythonify=True).attribute_count) >= self.config['max_attributes_per_event']

    def add_attribute(self, evetid, attr):
        try:
            self.misp.add_attribute(evetid, attr)
        except Exception as e:
            self.logger.error("Error while adding an attribute. Wait a second and try again")
            sleep(1)
            try:
                self.misp.add_attribute(evetid, attr)
            except Exception as e:
                self.logger.error("Second error for the attribute:")
                self.logger.error("Attribute: " + str(attr))
                self.logger.error('Eventid:' + str(evetid))
                self.logger.error(e)
                self.logger.error("Ignoring this attribute")
        return int(self.misp.get_event(evetid, pythonify=True).attribute_count) >= self.config['max_attributes_per_event']

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
        self.logger.info("Sighting added to attribute")

    def get_feed_events(self, feed_tag):
        erg = {}
        res = self.misp.search(tags=[feed_tag], controller='events', pythonify=True)
        for event in res:
            if int(event.attribute_count) >= self.config['max_attributes_per_event']:
                continue
            for tag in event.tags:
                if tag['name'].startswith("malware:"):
                    malware = tag['name'].split(':')[1]
                    erg[malware] = event.id
                    break
        return erg

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
        elif ft == 'apk':
            return 'file-type:type="android"'
        else:
            return 'file-type:type="' + ft + '"'
        return ''

    def new_misp_event(self, malware_type, feed_tag, event_info, additional_tags=[],
                       info_cred='admiralty-scale:information-credibility="2"'):
        malware_tag = "malware:" + malware_type
        misp_event_obj = MISPEvent()
        misp_event_obj.info = event_info
        misp_event_obj.add_tag(feed_tag)
        misp_event_obj.add_tag(info_cred)
        if len(malware_tag) > 0:
            misp_event_obj.add_tag(malware_tag)
        for tag in self.config['tags']:
            misp_event_obj.add_tag(tag)
        for tag in additional_tags:
            misp_event_obj.add_tag(tag)
        misp_event_obj.orgc = self.orgc

        galaxies = self.get_galaxies(malware_tag)
        for galaxy in galaxies:
            misp_event_obj.add_tag(galaxy)
        misp_event = self.misp.add_event(misp_event_obj)
        self.logger.info("New Event for Malware " + malware_type + " created")
        return misp_event


class AbuseChImporter:
    def __init__(self, logger, config):
        self.config = config
        self.mh = MispHandler(config, logger)
        self.misp = self.mh.misp
        self.logger = logger
        download_dir = config['download_dir']
        self.dl = AbuseChDownloader(logger, download_dir, self.config)
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
        misp_event_info = self.mh.get_feed_events(self.feed_tag)
        self.misp_events = misp_event_info


    def import_data(self):
        self.logger.info("Start import of file with " + str(sum(1 for line in open(self.infile))) + 'lines.')
        csvfile = open(self.infile, "r")

        new_iocs = 0
        already_known_iocs = 0

        for line in csvfile:
            if already_known_iocs == 10:
                self.logger.info("last 10 IOCs already were already in your MISP. Aborting...")
                break
            row = line.split('", "')
            if row[0].startswith("#") or len(row) < 12:
                self.logger.info("No IOC line, continue with next line")
                continue

            malware_type = row[8].strip().strip('"').lower()
            object = self.map_object(row)
            if object is None:
                self.logger.info("IOCs already imported, contine with next line")
                already_known_iocs = already_known_iocs + 1
                continue

            if malware_type in self.misp_events.keys():
                pass
            else:
                self.logger.info("New malware in this feed. Create new Event")
                event_info = "Malware Bazaar: " + malware_type
                event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info)
                self.misp_events[malware_type] = self.mh.get_event_id(event)

            if self.mh.add_object(self.misp_events[malware_type], object):
                self.logger.info("Max numbers of IOCs per Event reached. Publish Event and create a new Event for further IOCs")
                self.misp.publish(self.misp_events[malware_type])
                del self.misp_events[malware_type]

            self.logger.info("New Object added to Event")
            new_iocs = new_iocs + 1
            already_known_iocs = 0


        for malware_type in self.misp_events:
            self.misp.publish(self.misp_events[malware_type])
        self.logger.info("Bazaarimport finished - " + str(new_iocs) + "new objects imported")

    def map_object(self, row):
        misp_object = MISPObject("file")
        misp_object.name = "file"
        misp_object.first_seen = datetime.strptime(row[0].strip().strip('"'), '%Y-%m-%d %H:%M:%S')
        ft = row[6].strip().strip("")
        file_type = "File Type Guess: " + ft
        sha256 = row[1].strip().strip('"')
        tax = self.mh.get_file_taxonomy(ft)
        link = "https://bazaar.abuse.ch/sample/" + sha256

        res = self.misp.search(controller='attributes', value=link, tags=[self.feed_tag])
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
        self.misp_events = self.mh.get_feed_events(self.feed_tag)

    def import_data(self):
        self.logger.info("Start import of file with " + str(sum(1 for line in open(self.infile))) + ' lines.')
        csvfile = open(self.infile, "r")
        readCSV = csv.reader(csvfile, delimiter=',')
        existing_iocs = 0
        new_icos = 0

        for row in readCSV:
            if existing_iocs == 10:
                self.logger.info("last 10 IOCs were already in the MISP. Aborting....")
                break

            if row[0].startswith("#"):
                self.logger.info("No IOC line, continue with next line")
                continue

            malware_type = row[2].split(' ')[0]
            val = row[1].strip().strip('"')
            res = self.misp.search(controller='attributes', tags=[self.feed_tag], value=val, pythonify=True)
            if len(res) > 0:
                self.logger.info("Attribute already exits, continue with next line")
                existing_iocs = existing_iocs + 1
                continue


            if malware_type in self.misp_events:
                pass
            else:
                event_info = "C2 SSL Certificates: " + malware_type
                tags = []
                tags.append('common-taxonomy:malware="command-and-control"')
                tags.append('kill-chain:Command and Control')
                event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info, additional_tags=tags)
                self.misp_events[malware_type] = self.mh.get_event_id(event)

            new_attribute = self.map_attribute(row)
            if self.mh.add_attribute(self.misp_events[malware_type], new_attribute):
                self.logger.info(
                    "Max numbers of IOCs per Event reached. Publish Event and create a new Event for further IOCs")
                self.misp.publish(self.misp_events[malware_type])
                del self.misp_events[malware_type]
            new_icos = new_icos + 1
            existing_iocs = 0
            self.logger.info("New IOC added to MISP")


        for malware_type in self.misp_events:
            self.misp.publish(self.misp_events[malware_type])

        self.logger.info("SSL Certificate Importer finished")
        self.logger.info(str(new_icos) + ' ')

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
    def __init__(self, logger, config, import_agressive):
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
        self.misp_events = self.mh.get_feed_events(self.feed_tag)

    def import_data(self):
        self.logger.info("Start import of file with " + str(sum(1 for line in open(self.infile))) + ' lines.')
        csvfile = open(self.infile, "r")
        readCSV = csv.reader(csvfile, delimiter=',')
        malware_type = 'n/a'



        known_iocs = 0
        new_iocs = 0

        for row in readCSV:
            if known_iocs == 10:
                self.logger.info("Last 10 IOCs were already in the MISP. Aborting...")
                break

            if row[0].startswith("#"):
                self.logger.info("No IOC line, continue with next line")
                continue
            new_attribute = self.map_attribute(row)
            res = self.misp.search(controller='attributes', tags=[self.feed_tag], value=new_attribute.value.split('|')[0], pythonify=True)
            if len(res) > 0:
                self.logger.info("IOC already in MIPS, continue with next line")
                known_iocs = known_iocs + 1
                continue
            if malware_type not in self.misp_events:
                event_info = "C2 IPs identified by SSL Certificates"
                tags = []
                tags.append('common-taxonomy:malware="command-and-control"')
                tags.append('kill-chain:Command and Control')
                if self.import_agressive:
                    event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info, additional_tags=tags,
                                                   info_cred='admiralty-scale:information-credibility="3"')
                else:
                    event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info, additional_tags=tags)
                self.misp_events[malware_type] = self.mh.get_event_id(event)

            if self.mh.add_attribute(self.misp_events[malware_type], new_attribute):
                self.logger.info(
                    "Max numbers of IOCs per Event reached. Publish Event and create a new Event for further IOCs")
                self.misp.publish(self.misp_events[malware_type])
                del self.misp_events[malware_type]
            self.logger.info("New IOC added")
            known_iocs = 0
            new_iocs = new_iocs + 1

        for malware_type in self.misp_events:
            self.misp.publish(self.misp_events[malware_type])

        self.logger.info(str(new_iocs) + " IOCs imported")
        self.logger.info("SSL Blacklist IP importer finished")

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
        self.logger = logger
        self.import_agressive = import_agressive
        if import_agressive:
            url = 'https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv'
            self.logger.info("Import Feodotracker Agressive")
        else:
            url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv'
            self.logger.info("Import Feodotracker")
        super(FeodoImporter, self).__init__(logger, config)
        self.infile = self.dl.download_feed(url)

        self.type_index = 5
        if self.infile is None:
            self.logger.error("Download Error")
            self.error = True
        if self.import_agressive:
            self.feed_tag = 'feed:abusech="Feodo-tracker-agressive"'
        else:
            self.feed_tag = 'feed:abusech="Feodo-tracker"'
        self.misp_events = self.mh.get_feed_events(self.feed_tag)

    def import_data(self):
        self.logger.info("Start import of file with " + str(sum(1 for line in open(self.infile))) + ' lines.')
        csvfile = open(self.infile, "r")

        new_iocs = 0
        updated_iocs = 0
        not_updated_iocs = 0

        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            malware_type = ''
            if row[0].startswith("#") or len(row) < self.type_index or row[0].startswith('first'):
                self.logger.info("No IOC line, continue with next line")
                continue

            try:
                malware_type = row[self.type_index].strip().strip('"').lower()
            except IndexError as e:
                self.logger.error(e)

            if malware_type in self.misp_events:
                pass
            else:
                self.logger.info("New Malware in this Feed, create new event")
                event_info = "Feodo Tracker: " + malware_type

                tags = []
                tags.append('common-taxonomy:malware="command-and-control"')
                tags.append('kill-chain:Command and Control')
                if self.import_agressive:
                    info_cred = 'admiralty-scale:information-credibility="4"'
                else:
                    info_cred = 'admiralty-scale:information-credibility="2"'

                event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info, additional_tags=tags,
                                               info_cred=info_cred)

                self.misp_events[malware_type] = self.mh.get_event_id(event)

            new_attribute = self.map_attribute(row)
            res = self.misp.search(controller='attributes', value=new_attribute.value.split('|')[0],
                                   tags=[self.feed_tag], pythonify=True)
            if len(res) > 0:
                attribute = res[0]
                ls_string = row[4].strip().strip('"')

                if ls_string != '' and hasattr(attribute, 'last_seen'):
                    ls = datetime.strptime(ls_string, '%Y-%m-%d')
                    ls = ls.replace(tzinfo=pytz.UTC)
                    if ls > attribute.last_seen:
                        attribute.last_seen = ls

                    if row[3] == 'online':
                        self.mh.add_sigthing(attribute.id)
                        self.misp.update_attribute(attribute, attribute.id)
                        self.logger.info("Attribute updated and sighting added")
                        updated_iocs = updated_iocs + 1
                    else:
                        self.logger.info("'last_seen' is not newer than in MISP. Attribute not changed")
                        not_updated_iocs = not_updated_iocs + 1
                else:
                    self.logger.info("last seen value not in feed for existing IOC:" + new_attribute.value)
                    not_updated_iocs = not_updated_iocs + 1
            else:
                if self.mh.add_attribute(self.misp_events[malware_type], new_attribute):
                    self.logger.info(
                        "Max numbers of IOCs per Event reached. Publish Event and create a new Event for further IOCs")
                    self.misp.publish(self.misp_events[malware_type])
                    del self.misp_events[malware_type]
                self.logger.info("New attriubte added")
                new_iocs = new_iocs + 1

        for malware_type in self.misp_events:
            self.misp.publish(self.misp_events[malware_type])
        self.logger.info(str(new_iocs) + " new iocs imported.")
        self.logger.info(str(not_updated_iocs) + ' IOCs were already up to date')
        self.logger.info(str(updated_iocs) + ' IOCs updated')
        self.logger.info("FeodoTracker import finished")

    def map_attribute(self, row):
        misp_attribute = MISPAttribute()
        fs = datetime.strptime(row[0].strip().strip('"'), '%Y-%m-%d %H:%M:%S')
        misp_attribute.first_seen = fs
        try:
            ls_string = row[4].strip().strip('"')
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
        self.misp_events = self.mh.get_feed_events(self.feed_tag)
        self.IPRE = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

    def import_data(self):
        self.logger.info("Start import of file with " + str(sum(1 for line in open(self.infile))) + ' lines.')
        csvfile = open(self.infile, "r")

        new_iocs = 0
        updated_iocs = 0
        known_iocs = 0

        for line in csvfile:
            if known_iocs == -10:
                self.logger.info("last 10 IOCs were already in the MISP. Aborting....")
                break
            row = line.split('","')
            if row[0].startswith("#"):
                self.logger.info("No IOC line, continue with next line")
                continue

            res = self.misp.search(controller='attributes', value=row[2].strip().strip('"'), pythonify=True, tags=[self.feed_tag])
            if len(res) > 0:
                if self.feed == 'online':
                    attribute = res[0]

                    self.mh.add_sigthing(attribute.id)
                    attribute.last_seen = datetime.now()
                    self.misp.update_attribute(attribute, attribute.id)
                    self.logger.info("Sighting added " + datetime.now().strftime("%H:%M:%S"))
                    updated_iocs = updated_iocs + 1
                else:
                    known_iocs = known_iocs + 1
                continue


            malware_info = self.get_malware_info(row)
            malware_type = malware_info['mt'].lower()
            if malware_type == '':
                malware_type = "n/a"
            ft = malware_info['ft']

            if malware_type not in self.misp_events:
                event_info = "UrlHaus Malware URLs: " + malware_type
                tags = []
                info_cred = 'admiralty-scale:information-credibility="2"'
                event = self.mh.new_misp_event(malware_type, self.feed_tag, event_info, additional_tags=tags, info_cred=info_cred)
                self.misp_events[malware_type] = self.mh.get_event_id(event)

            if self.config['save_url_as'] == 'attribute':
                attr = self.map_attribute(row)
                if ft is not None:
                    attr.add_tag(ft)

                if self.mh.add_attribute(self.misp_events[malware_type], attr):
                    self.logger.info(
                        "Max numbers of IOCs per Event reached. Publish Event and create a new Event for further IOCs")
                    self.misp.publish(self.misp_events[malware_type])
                    del self.misp_events[malware_type]
                self.logger.info("URL added to event")
            elif self.config['save_url_as'] == 'object':
                if self.map_object(row, self.misp_events[malware_type]):
                    self.logger.info(
                        "Max numbers of IOCs per Event reached. Publish Event and create a new Event for further IOCs")
                    self.misp.publish(self.misp_events[malware_type])
                    self.logger.info("URL Object added to event " + str(self.misp_events[malware_type]))
                    del self.misp_events[malware_type]
                else:
                    self.logger.info("URL Object added to event " + str(self.misp_events[malware_type]))
            else:
                self.logger.error("Invalid config: 'save_url_as' has to be 'attribute' or 'object'")
                exit(1)
            new_iocs = new_iocs + 1
            known_iocs = 0

        for malware_type in self.misp_events:
            self.misp.publish(self.misp_events[malware_type])

        self.logger.info(str(new_iocs) + ' IOCs imported')
        self.logger.info("Urlhaus import finished")

    def map_object(self, row, evetid):
        malware_info = self.get_malware_info(row)
        value = row[2].strip().strip('"')
        f = Faup()
        f.decode(value)
        misp_obj = MISPObject('url')
        misp_obj.name = "url"

        misp_obj.add_attributes('url', value)
        if re.search(self.IPRE, f.get_domain()):
            misp_obj.add_attributes('ip', f.get_domain())
        else:
            misp_obj.add_attributes('host', f.get_host())
            misp_obj.add_attributes('domain', f.get_domain())
            misp_obj.add_attributes('domain_without_tld', f.get_domain_without_tld())
        misp_obj.add_attributes('port', f.get_port())
        misp_obj.add_attributes('query_string', f.get_query_string())
        misp_obj.add_attributes('resource_path', f.get_resource_path())
        misp_obj.add_attributes('scheme', f.get_scheme())
        misp_obj.add_attributes('subdomain', f.get_subdomain())
        misp_obj.add_attributes('tld', f.get_tld())
        misp_obj.add_attributes('credential', f.get_credential())

        misp_obj.add_attributes('fragment', f.get_fragment())
        misp_obj.add_attributes('text', row[6].strip().strip('"'))

        fs = datetime.strptime(row[1].strip().strip('"'), '%Y-%m-%d %H:%M:%S')
        misp_obj.first_seen = fs
        misp_obj.last_seen = fs

        if row[4].strip().strip('"') == "malware_download":
            misp_obj.get_attributes_by_relation('url')[0].add_tag('kill-chain:Delivery')
        if malware_info['ft'] is not None:
            misp_obj.get_attributes_by_relation('url')[0].add_tag(malware_info['ft'])
        misp_obj.get_attributes_by_relation('url')[0].add_tag('urhaus_reporter:' + row[7].strip().strip('"'))
        misp_obj.get_attributes_by_relation('text')[0].comment = 'External Analysis'
        for relation in ['ip', 'host', 'domain']:
            try:
                misp_obj.get_attributes_by_relation(relation)[0].to_ids = False
            except:
                continue

        return self.mh.add_object(evetid, misp_obj)

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
        misp_attribute.add_tag('urhaus_reporter:' + row[7].strip().strip('"'))
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
                        choices=['DEBUG', "INFO", "WARNING", "ERROR", 'CRITICAL'], default='DEBUG')

    args = parser.parse_args()
    logger = init_logger(args.loglevel)
    pymisplogger = logging.getLogger('pymisp')
    pymisplogger.setLevel('ERROR')
    config = load_config(args.config, logger)

    if 'log_level' in config:
        logger.setLevel(logging.getLevelName(config['log_level']))

    bi = BazaarImporter(logger, config, full_import=config['MalwareBazaarImportFull'])
    if not bi.error:
        bi.import_data()
    fi = FeodoImporter(logger, config, import_agressive=config['FeodoTrackerImportAggressive'])
    if not fi.error:
        fi.import_data()
    si = SSLBLImporter(logger, config)
    if not si.error:
        si.import_data()
    si = SSLBLIPImporter(logger, config, import_agressive=config['SSLBlackListImportAggressiveIPs'])
    if not si.error:
        si.import_data()
    ui = UrlHausImporter(logger, config, feed=config['UrlHausFeed'])
    if not ui.error:
        ui.import_data()
