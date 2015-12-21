
from virustotal import *
import postfile
import os,sys
import json
import sendmail
import sendsms

def findapk(filePath):
    filePath = apkfiledir  + '/scaned_apk'
    if not os.path.exists(apkfiledir):
        os.mkdir(apkfiledir)
    for item in os.listdir(filePath):
        curItem = filePath + '/' + item
        if os.path.isfile(curItem):
            if (".apk" == os.path.splitext(item)[1]): 
                print curItem
                return curItem
            else:
                pass
    return ""


def uploadapk(scanfile): # Hash of resource
    scanresults = v.rscScan(scanfile)
    md5 = ""
    scanresults = json.loads(scanresults)
    for item in scanresults:

            if item == "response_code":
                print "response_code:", scanresults[item]
            if item == "md5":
                print "md5sum:", scanresults[item]
                md5 = scanresults[item]
    return md5


def scanReport(md5):
    results = v.rscReport(md5)
    resultfanal = ['','','','','','']
    for item in results:
            if item == "resource":
                print "Grabbing last submitted report for:", results[item]
            if item == "permalink":
                print "Report link:", results[item]
                resultfanal[0] = "Report link:" + results[item]
            if item == "md5":
                print "md5:", results[item]
                resultfanal[1] = "md5:" + results[item]
            if item == "scan_date":
                print  "Last scanned:", results[item]
                resultfanal[2] = "Last scanned:" + results[item]
            if item == "positives":
                print "Positive hits:", results[item]
                resultfanal[3] = results[item] #"Positive hits:" 
            if item == "total":
                print "Total AVs tested:", results[item]
                resultfanal[4] = results[item] #"Total AVs tested:"
            if item == "scans":
                for item1 in results[item]:
                    for item2 in results[item][item1]:
                        if item2 == "detected" and results[item][item1][item2] == True:
                            resultfanal[5] += item2 + ","

                print "be reported", resultfanal[5]  #"Total AVs tested:"

    return resultfanal


v = Virustotal()
# apkfilepath = findapk(os.getcwd())
apkfiledir = os.path.dirname(os.path.realpath(__file__))
apkfilepath = findapk(apkfiledir)

if apkfilepath:
    apkmd5 = uploadapk(apkfilepath)
    report = scanReport(apkmd5)
    if not report[4] == 0 and not report[4] == '':
        if not report[3] == 0 and not report[3] == '':
            smsreportcontext = 'Tested %s antivirus, there is %s virus being reported' %(report[4],report[3])
            print smsreportcontext
            sendsms.smssendrepare(smsreportcontext)
            try:
                sendmail.runsendemail(report,apkfilepath)
                pass
            except Exception, e:
                print 'error:%s' %e
                print 'send email failed.'
    else:
        pass




    

# Report link: https://www.virustotal.com/file/b7ab5bcd4edfd8ac7be17dd0650e01c4d519814784609851be9b2df571e501f3/analysis/1396511495/
# Grabbing last submitted report for: 9c064772651a14ca8936d02d98f843ed
# Last scanned: 2014-04-03 07:51:35
# Total AVs tested: 50
# Positive hits: 48
# md5sum: 9c064772651a14ca8936d02d98f843ed
# ```



# ### Post comment
# ```python
# >>> # Post comment about resource
# ... from virustotal import *
# >>> rsc = "9c064772651a14ca8936d02d98f843ed" # Hash of resource to post comment about
# >>> comment = "Captured with #honeypot #dionaea"
# >>> v = Virustotal()
# >>> results = v.postComment(rsc, comment)
# Your comment was successfully posted
# Report link: https://www.virustotal.com/file/b7ab5bcd4edfd8ac7be17dd0650e01c4d519814784609851be9b2df571e501f3/analysis/1396511495/
# ```

# ### Get URL report or submit for scan
# ```python
# >>> # Check domain for report if no results submit it for a scan
# >>> v = Virustotal()
# >>> dchk = v.domainReport(rsc)
# >>> if dchk["response_code"] == 0:
# ...         print "No dataset found for %s" %(rsc)
# ...         print "Running scan for resource..."
# ...         results = v.scanURL(rsc)
# ...         for item in results:
# ...                 if item == "permalink":
# ...                         print "Check link below for results:"
# ...                         print results[item]
# ... else:
# ...         for item in dchk:
# ...                 if item == "scan_date":
# ...                         print "Last scanned:", dchk[item]
# ...                 if item == "permalink":
# ...                         print "Results link:", dchk[item]
# ...
# No dataset found for www.norcaljazzfestival.com
# Running scan for resource...
# Check link below for results:
# https://www.virustotal.com/url/d5a5c2532462ed8dda2324f1967916dc4c5c1aa828dce4c5cd7459c8084f7084/analysis/1396592916/
# ```
