__author__ = 'Charlie'
import json
import spam.spamhaus; from surblclient import surbl
from virus_total_apis import PublicApi as vtApi
vtURLKey = vtApi("72567edcd2b6af6da376b765f73b867fa7fe8606b9fab0e5319f4504eb6fce55")

# url_report is asynchronous, need to wait for completion
def responseWait(responseURL):
	checkJSON = "None"
	checkJSON = vtURLKey.get_url_report(responseURL)
	return checkJSON

# gets/evals JSON data
def vtUrlCheck(vtURL):
	response = responseWait(vtURL)
	if response["results"]["response_code"] == "0":
		vtUrlCheck(vtURL)
	elif response["results"]["response_code"] == "1":
		if response["results"]["positives"] != 0:
			return True
		else:
			return False
	elif response["results"]["response_code"] == "-1":
		return "FUBAR"
	else:
		return False

# URL checking logic, only does as much as it needs
def urlIsMalicious(site):
	try:
		checkerHaus = spam.spamhaus.SpamHausChecker()
		hausSpamResult = checkerHaus.is_spam(site) ; surblSpamResult = (site in surbl)
		if hausSpamResult and surblSpamResult:
			return True
		elif bool(hausSpamResult) ^ bool(surblSpamResult):
			if vtUrlCheck(site):
				return True
			elif vtUrlCheck(site) == "FUBAR":
				return False
			else:
				return False
		else:
			return False
	except:
		return False

# handler method
def checkURL(url):
	if urlIsMalicious(url):
		return True
	else:
		return False