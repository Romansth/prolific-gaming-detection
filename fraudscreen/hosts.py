"""Host lists. Matching is exact host or sub-domain of a listed registrable domain; never a
substring of the URL (brand names inside paths and blobs produced false hits in the audit)."""
import functools

ANTIDETECT = ("adspower.net", "adspower.com", "gologin.com", "multilogin.com", "multilogin.io", "dolphin-anty.com",
              "anty.dolphin.ru.com", "octobrowser.net", "incogniton.com", "kameleo.io", "morelogin.com", "ixbrowser.com",
              "undetectable.io", "vmlogin.com", "vmlogin.us", "lalicat.com", "hidemyacc.com", "nstbrowser.io",
              "bitbrowser.net", "ghostbrowser.com", "sessionbox.io")
IPCHECK = ("whoer.net", "whoer.to", "pixelscan.net", "iphey.com", "browserleaks.com", "amiunique.org", "ipfighter.com",
           "whatismyipaddress.com", "ipinfo.io", "iplocation.net", "dnsleaktest.com", "ipleak.net", "showmyip.com",
           "whatismyip.com", "ipchicken.com", "myip.com", "ip2location.com", "browserscan.net", "abrahamjuliot.github.io",
           "coveryourtracks.eff.org", "bot.sannysoft.com", "deviceinfo.me", "ip.me", "ifconfig.me", "icanhazip.com",
           "ipaddress.my", "whatsmyip.org", "iplocation.io", "ip8.com", "2ip.io", "2ip.ru", "ipqualityscore.com",
           "scamalytics.com", "whatismybrowser.com", "ipapi.co", "ip-api.com", "ipgeolocation.io", "db-ip.com",
           "maxmind.com", "ip-score.com", "fingerprint.com", "fingerprintjs.com", "creepjs.com", "ipify.org")
VPN_ACCOUNT_HOSTS = ("my.nordaccount.com", "nordaccount.com", "order.nordvpn.com", "order.nordaccount.com",
                     "account.protonvpn.com", "my.surfshark.com", "account.expressvpn.com", "checkout.expressvpn.com",
                     "my.windscribe.com", "account.ipvanish.com", "my.privateinternetaccess.com", "my.cyberghostvpn.com",
                     "account.purevpn.com", "my.hide.me")
VPN = ("nordvpn.com", "nordaccount.com", "expressvpn.com", "surfshark.com", "protonvpn.com", "mullvad.net",
       "windscribe.com", "cyberghostvpn.com", "ipvanish.com", "privateinternetaccess.com", "hide.me", "tunnelbear.com",
       "purevpn.com", "urban-vpn.com", "urbanvpn.com", "hola.org", "hotspotshield.com", "atlasvpn.com", "privadovpn.com",
       "vpnunlimited.com", "zenmate.com", "browsec.com", "touchvpn.net", "betternet.co", "astrill.com", "torguard.net",
       "ivpn.net", "veepn.com", "hidemyass.com", "setupvpn.com", "hoxx.com", "x-vpn.com", "itopvpn.com")
PROXY = ("earnapp.com", "honeygain.com", "pawns.app", "packetstream.io", "peer2profit.com", "traffmonetizer.com",
         "repocket.com", "iproyal.com", "brightdata.com", "luminati.io", "oxylabs.io", "smartproxy.com", "decodo.com",
         "proxyrack.com", "soax.com", "nodemaven.com", "proxy-cheap.com", "ipburger.com", "922proxy.com", "pyproxy.com",
         "proxyempire.io", "proxy-seller.com", "webshare.io", "geonode.com", "getgrass.io", "mysterium.network",
         "lunaproxy.com", "abcproxy.com", "thordata.com")
REMOTE = ("anydesk.com", "teamviewer.com", "parsec.app", "rustdesk.com", "splashtop.com", "remotedesktop.google.com",
          "logmein.com", "getscreen.me", "ultraviewer.net", "hoptodesk.com", "remotepc.com", "dwservice.net")
SMS = ("sms-activate.org", "sms-activate.io", "sms-activate.guru", "5sim.net", "smspva.com", "smshub.org",
       "textverified.com", "onlinesim.io", "getsmscode.com", "sms-man.com", "grizzlysms.com", "receive-smss.com",
       "receive-sms-free.cc", "quackr.io")
TEMPMAIL = ("temp-mail.org", "10minutemail.com", "guerrillamail.com", "mailinator.com")
GENERATOR = ("fakenamegenerator.com", "randomuser.me", "fakepersongenerator.com", "fakeaddressgenerator.com",
             "namefake.com", "fauxid.com", "elfqrin.com", "usaddressgenerator.com")
CHATBOT = ("chatgpt.com", "chat.openai.com", "gemini.google.com", "claude.ai", "copilot.microsoft.com", "perplexity.ai",
           "chat.deepseek.com", "grok.com", "poe.com")
SURVEY_INFRA = ("prolific.com", "prolific.co", "conjointly.online", "qualtrics.com", "cloudresearch.com", "typeform.com",
                "boltinsight.com", "voxpopme.com", "dscout.com", "conveo.ai", "outset.ai", "surveymonkey.com",
                "audacious-software.com", "alchemer.com", "alchemer.eu", "decipherinc.com", "sawtoothsoftware.com",
                "pavlovia.org", "limesurvey.net", "yougov.com", "samplicio.us", "focaldata.com", "gorilla.sc", "maze.co",
                "playbookux.com", "respondent.io", "userinterviews.com", "dialogueai.com", "tellet.ai", "credamo.app",
                "reachcollective.com", "questionpro.com", "surveycto.com", "jotform.com", "mturk.com", "cint.com",
                "purespectrum.com", "prodege.com", "swagbucks.com", "inboxdollars.com", "ysense.com", "toluna.com",
                "opinionoutpost.com", "pollfish.com", "simile.ai", "listenlabs.ai", "usertesting.com")
DASHBOARD = ("app.prolific.com", "connect.cloudresearch.com")
US_CONSUMER = ("chase.com", "bankofamerica.com", "wellsfargo.com", "capitalone.com", "citi.com", "usbank.com", "pnc.com",
               "truist.com", "navyfederal.org", "usaa.com", "discover.com", "americanexpress.com", "venmo.com", "cash.app",
               "zellepay.com", "walmart.com", "target.com", "costco.com", "kroger.com", "homedepot.com", "lowes.com",
               "cvs.com", "walgreens.com", "xfinity.com", "spectrum.net", "att.com", "verizon.com", "t-mobile.com",
               "usps.com", "ups.com", "fedex.com", "irs.gov", "ssa.gov", "healthcare.gov", "doordash.com", "grubhub.com",
               "zillow.com", "indeed.com")
TRAVEL = ("kayak.com", "expedia.com", "booking.com", "airbnb.com", "hotels.com", "priceline.com", "tripadvisor.com",
          "orbitz.com", "united.com", "delta.com", "aa.com", "southwest.com", "jetblue.com", "aeromexico.com", "volaris.com",
          "vivaaerobus.com", "copaair.com", "latam.com", "latamairlines.com", "avianca.com", "aerolineas.com.ar",
          "kenya-airways.com", "ethiopianairlines.com", "emirates.com", "qatarairways.com", "turkishairlines.com",
          "klm.com", "britishairways.com", "ryanair.com", "easyjet.com", "lufthansa.com")
TRAVEL_LABELS = ("skyscanner", "airfrance")   # any TLD

FRAUD_SIGNAL_HOSTS = tuple(sorted(set(ANTIDETECT + IPCHECK + VPN + VPN_ACCOUNT_HOSTS + PROXY + REMOTE + SMS + TEMPMAIL + GENERATOR)))
ANTIDETECT_LAUNCH = (("start.adspower.net", "/"),)
ANTIDETECT_LAUNCH_QUERY = "host=127.0.0.1:"

_GROUPS = [("vpn_account", VPN_ACCOUNT_HOSTS, True), ("dashboard", DASHBOARD, True), ("antidetect", ANTIDETECT, False),
           ("ipcheck", IPCHECK, False), ("vpn_marketing", VPN, False), ("proxy", PROXY, False), ("remote", REMOTE, False),
           ("sms", SMS, False), ("tempmail", TEMPMAIL, False), ("generator", GENERATOR, False), ("chatbot", CHATBOT, False),
           ("survey_infra", SURVEY_INFRA, False), ("us_consumer", US_CONSUMER, False), ("travel", TRAVEL, False)]


def _in(host, domains, exact):
    if exact:
        return host in domains
    return any(host == d or host.endswith("." + d) for d in domains)


@functools.lru_cache(maxsize=1 << 16)
def classify(host):
    host = (host or "").lower()
    if not host:
        return None
    for name, domains, exact in _GROUPS:
        if _in(host, domains, exact):
            return name
    if host.endswith(".gov") or host.endswith(".mil"):
        return "us_consumer"
    labels = host.split(".")
    if any(l in TRAVEL_LABELS for l in labels):
        return "travel"
    return None


def is_signal_host(host):
    return _in((host or "").lower(), FRAUD_SIGNAL_HOSTS, False)


def is_travel(host, path=""):
    if classify(host) == "travel":
        return True
    return (host or "").lower() in ("www.google.com", "google.com") and (path or "").startswith("/travel")
