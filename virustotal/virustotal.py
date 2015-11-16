# Virustotal Module
#
# Below are a Virustotal.com's API options/tags (for k:v responses)
# response_code, verbose_msg
# resource, scan_id, md5, sha1, sha256
# scan_date
# scans

__author__ = 'Dai'

import requests
import json
import postfile

class Virustotal():
	""" Virustotal API module """
	def __init__(self):
		self.host = "www.virustotal.com"
		self.basescan = "/vtapi/v2/"
		self.base = "https://www.virustotal.com/vtapi/v2/"
		self.apikey = "40ba7ed7e7201cce65a1a0bbe780b27f0fe7f964ba9adc7e75cbdb5747c8dd74"
		self.apikeyscan = [("apikey", "40ba7ed7e7201cce65a1a0bbe780b27f0fe7f964ba9adc7e75cbdb5747c8dd74")]

	def rscScan(self,scanfile):
		""" Virustotal API module """
		base = self.basescan + 'file/scan'
		file_to_send = open(scanfile , "rb").read()
		files = [("file", scanfile , file_to_send)]
		print 'sending...'
		json = postfile.post_multipart(self.host, base, self.apikeyscan, files)
		return json

	def rscReport(self, rsc):
		""" Get latest report of resource """

		base = self.base + 'file/report'
		parameters = {"resource":rsc, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results

	def urlReport(self, rsc, scan=0):
		""" Get latest report URL scan report of resource """

		base = self.base + 'url/report'
		parameters = {"resource":rsc, "scan":scan, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results

	def ipReport(self, rsc):
		""" Get latest report for IP Address """

		base = self.base + 'ip-address/report'
		parameters = {"ip":rsc, "apikey":self.apikey}
		r = requests.get(base, params=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results

	def domainReport(self, rsc):
		""" Get latest report for IP Address """

		base = self.base + 'domain/report'
		parameters = {"domain":rsc, "apikey":self.apikey}
		r = requests.get(base, params=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results
		
	def scanURL(self, rsc):

		""" Send RSC/URL for scanning; Its encouraged to check for last scanusing urlReport()
		To submit batch rsc should be example.com\nexample2.com"""

		base = self.base + 'url/scan'
		parameters = {"url":rsc, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results

	def rscSubmit(self, rsc):

		""" Submit potential malicious file to virustotal for analyzing """
		base = self.base + 'file/scan'
		f = open(rsc, 'rb')
		parameters = {"apikey":self.apikey}
		r = requests.post(base, data=parameters, files={'file':f})
		resp = r.json()
		results = parse_resp(resp)
		return results

	def rscRescan(self, rsc):

		""" Rescan potential malicious file to virustotal for analyzing without uploading the file again """
		base = self.base + 'file/rescan'
		parameters = {"resource":rsc, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results

	def postComment(self, rsc, comment):

		""" Post comment to files or urls """
		base = self.base + 'comments/put'
		parameters = {"resource":rsc, "comment":comment, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		results = parse_resp(resp)
		if results['response_code'] == 0:
			print "Oh no something happen...cant post comment"
		else:
			print "Your comment was successfully posted"
			call = self.rscReport(rsc)
			for item in call:
				if item == "permalink":
					print "Report link:", call[item]


def parse_resp(resp):
	""" Parses the response from the requests.gets/posts()
	then returns the data back to the function """
	buf = {}
	for item in resp:
		buf[item] = resp[item]

	return buf
