from ssllabsscan.notify import *

def quality_check(host, grade, warnings):
    quality_ok = True

    if (grade != "A+" and grade != "A"):
        quality_ok = False

    if (warnings == True):
        quality_ok = False

    if (not quality_ok):
        notify(host)