from flask import Flask, render_template, request, redirect, make_response
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import requests
import time
import zlib
import pdfkit
#from bs4 import BeautifulSoup

CLEAN_HASHES = ["1fa8613a1e616106a96a38ecb185f42328f9e1b39573a292aff1d7b2733f1fa8",
                "f9c94a4743f2f798df2eb5728b0006baaede5534a31e0b4e26c2dedbc6c88ae5",
                "1b5a9f300de44dc24bf6f6735f97c60e0acfe0fd3b49350c5cc5141452768960"
                ]

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///localHashes.db'
current_user = 0
db = SQLAlchemy(app)

NUMBERS = ["0",'1','2','3','4','5','6','7','8','9']
SPECIAL = ["!", "@", "#", "$", "%", "^", "&", "*", "?"]
RULING = ["safe", "suspicious", "malicious"]
SENTENCE = ["This file is probably harmless and is not a threat to your computer.",
            "This file may be part of a PUP, or potentially unwanted program. While PUPs may not be directly harmful, they may access and log data and send it to a company without your knowledge. Otherwise, a PUP could be adware orsome other similar program.",
            "This file is flagged as malicious by many security vendors. It is recommended to not open the file an remove it as soon as possible. Malicious files can cause a wide variety of problems for your computer, hidden or otherwise."]
COLORS = ["#2b8f22", "#c1bb49", "#b70d29"]

@app.route('/')
def home():
    return render_template("home.html", user=current_user)

@app.route('/local')
def local():
    hashes = select_all()
    return render_template("local.html", hashes=hashes, user=current_user)

@app.route('/search', methods=['POST', 'GET'])
def search():
    #protects against no input search
    if not request.form['searched']:
        return render_template('home.html', user=current_user)
    #find if hash is md5 in local database
    if current_user != 0:
        update_history(current_user, request.form['searched'])
    input = request.form['searched']
    exist = md5Exists(input)
    #if not md5 find if sha256 in local database
    if not exist:
        exist = shaExists(input)
        if exist:
            input = getmd5(input)
    #if input is md5 or sha256 in local database
    if exist:
        #get relevant information from local table
        hash = getHash(input)
        who = hash[9]
        who = who.split(",")
        for i in range(len(who)):
            who[i] = who[i].strip()
        vend = hash[5]
        vend = vend.split(",")
        for i in range(len(vend)):
            vend[i] = vend[i].strip()
        if len(who)*3 > len(vend):
            mal = RULING[2]
            color = COLORS[2]
            sentence = SENTENCE[2]
        elif len(who)*5 > len(vend):
            mal = RULING[1]
            color = COLORS[1]
            sentence = SENTENCE[1]
        else:
            mal = RULING[0]
            color = COLORS[0]
            sentence = SENTENCE[0]
        for thing in who:
            if thing in vend:
                vend.remove(thing)
        names = hash[4].split(",")
        for i in range(len(names)):
            names[i] = names[i].strip()
        #by this point all information needed to be displayed is in respective variables
        #render the search results page and display the information
        if request.method == "POST":
            try:
                db.session.commit()
                return render_template("local.html",hash=hash,mal=mal,who=who,names=names, color = color, sentence=sentence, vend=vend, user=current_user, not_flagged = len(vend))
            except:
                return
        else:
            return render_template("search.html",id_to_search=hash, user=current_user)
    #in the case the searched hash was not in local database
    else:
        #set up needed variables for api call
        url = "https://www.virustotal.com/api/v3/files/" + input
        # janna's api key
        headers = {"Accept": "application/json",
                   "x-apikey": "14c2f2dc80480dd86c00ec8b1756cf503f1e122c16381930b91643a3cb474d4e"}
        #if api call successful load in json file
        try:
            response = requests.get(url, headers=headers).json()
        #if api call unsuccessful inform user
        except:
            return "Error communicating with the VirusTotal API."
        #use json file to find all the needed information
        results, vend_mal, info, vendors =make_api_call(response)
        #use case for hash not found on virustotal search
        if results == "error":
            return render_template("not_found.html", user=current_user)
        #if hash found information will be returned
        #add hash to database
        #view results to the user
        else:
            apiAdd(info, results, vend_mal, vendors)
            exist = md5Exists(input)
            # if not md5 find if sha256 in local database
            if not exist:
                exist = shaExists(input)
                if exist:
                    input = getmd5(input)
            # if input is md5 or sha256 in local database
            if exist:
                # get relevant information from local table
                hash = getHash(input)
                who = hash[9]
                who = who.split(",")
                for i in range(len(who)):
                    who[i] = who[i].strip()
                vend = hash[5]
                vend = vend.split(",")
                for i in range(len(vend)):
                    vend[i] = vend[i].strip()
                if len(who) * 3 > len(vend):
                    mal = RULING[2]
                    color = COLORS[2]
                    sentence = SENTENCE[2]
                elif len(who) * 5 > len(vend):
                    mal = RULING[1]
                    color = COLORS[1]
                    sentence = SENTENCE[1]
                else:
                    mal = RULING[0]
                    color = COLORS[0]
                    sentence = SENTENCE[0]
                for thing in who:
                    if thing in vend:
                        vend.remove(thing)
                names = hash[4].split(",")
                for i in range(len(names)):
                    names[i] = names[i].strip()
                # by this point all information needed to be displayed is in respective variables
                # render the search results page and display the information
                if request.method == "POST":
                    try:
                        db.session.commit()
                        return render_template("local.html", hash=hash, mal=mal, who=who, names=names, color=color,
                                               sentence=sentence, vend=vend, user=current_user, not_flagged=len(vend))
                    except:
                        return
                else:
                    return render_template("search.html", id_to_search=hash, user=current_user)

@app.route('/download/<md5>')
def download(md5, methods=['POST', 'GET']):
    if request.method == "GET":
        input = md5
        hash = getHash(input)
        who = hash[9]
        who = who.split(",")
        for i in range(len(who)):
            who[i] = who[i].strip()
        vend = hash[5]
        vend = vend.split(",")
        for i in range(len(vend)):
            vend[i] = vend[i].strip()
        if len(who) * 3 > len(vend):
            mal = RULING[2]
            color = COLORS[2]
            sentence = SENTENCE[2]
        elif len(who) * 5 > len(vend):
            mal = RULING[1]
            color = COLORS[1]
            sentence = SENTENCE[1]
        else:
            mal = RULING[0]
            color = COLORS[0]
            sentence = SENTENCE[0]
        for thing in who:
            if thing in vend:
                vend.remove(thing)
        names = hash[4].split(",")
        for i in range(len(names)):
            names[i] = names[i].strip()


        rendered = render_template("search.html",hash=hash,mal=mal,who=who,names=names, color = color, sentence=sentence, vend=vend, user=current_user, not_flagged = len(vend))
        pdf = pdfkit.from_string(rendered, False)

        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=VirusProtect_results.pdf'
        return response

@app.route('/help')
def help():
    return render_template("help.html", user=current_user)

@app.route('/sign_up', methods=['POST', 'GET'])
def sign_up():
    if request.method == "POST":
        adding = addUser(request.form["username_su"],request.form["password_su"],request.form["password_su_conf"],request.form["fname"],request.form["lname"],request.form["email"])
        if adding == "Login successful":
            user_info = get_user(current_user)
            history = user_info[6].split(",")
            if not user_info[3]:
                email = 0
            else:
                email = 1
            return render_template("account.html", user=current_user, info=user_info, history=history, email=email)
        else:
            return render_template("sign_up.html", error=adding, user=current_user)
    else:
        return render_template("sign_up.html", error=0, user=current_user)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        if request.form["username"] and request.form["password"]:
            login = log_in(request.form["username"], request.form["password"])
            if login == "Login successful":
                user_info = get_user(current_user)
                history = user_info[6].split(",")
                if not user_info[3]:
                    email = 0
                else:
                    email = 1
                return render_template("account.html", user=current_user, info=user_info, history=history, email=email)
            else:
                return render_template("sign_up.html", error=login, user=current_user)
        else:
            return redirect('/sign_up')
    else:
        return redirect('/sign_up')

@app.route('/log_out', methods=['POST', 'GET'])
def log_out():
    global current_user
    current_user = 0
    return redirect('/')

@app.route('/account', methods=['POST', 'GET'])
def account():
    user_info = get_user(current_user)
    history = user_info[6].split(",")
    if not user_info[3]:
        email = 0
    else:
        email = 1
    return render_template("account.html", user=current_user, info=user_info, history=history, email=email)

@app.route('/password', methods=['POST', 'GET'])
def password():
    if request.method == "POST":
        result = change_password(request.form["old"], request.form["new1"], request.form["new2"])
        return render_template("password.html", user=current_user, result=result)
    else:
        return render_template("password.html", user=current_user, result=0)

@app.route('/email', methods=['POST', 'GET'])
def email():
    if request.method == "POST":
        result = add_email(request.form["email"])
        if result  == "success":
            return redirect('/account')
        else:
            return render_template("email.html", user=current_user, result=result)
    else:
        return render_template("email.html", user=current_user, result=0)

def make_api_call(data):
    """
    :param data: possible dictionary
    :return: all required information about a hash
    """
    if 'data' in data:
        #parse the dictionary for relevant information
        data = data['data']
        att = data['attributes']
        #number of malicious flags
        malicious = att['last_analysis_stats']['malicious']
        #number of undetected flags
        undetected = att['last_analysis_stats']['undetected']
        #number of unsupported flags
        unsupported = att['last_analysis_stats']['type-unsupported']
        #find total number of vendors that gave a flag to the hash
        total = 0
        for num in att['last_analysis_stats']:
            if num in ['malicious', 'undetected']:
                total += att['last_analysis_stats'][num]
        #create lists for information needed
        vend_mal = []
        vendors = []
        keys =[]
        #mark as malicious if a third of the vendors marked it as malicious
        if malicious*3 > total:
            mal=RULING[2]
        elif malicious*5>total:
            mal = RULING[1]
        else:
            mal=RULING[0]
        #puts most of the metadata required into a list
        info= [att['size'], att['md5'], att['sha256'], att['names'], data['type'], mal,  att['type_description']]
        #make a list of vendors
        for vend in att['last_analysis_results']:
            vendors.append(vend)
            #make a sublist of vendors that flagged as malicious
            if att['last_analysis_results'][vend]['category'] == "malicious":
                vend_mal.append(vend)
        #returns all relevant information to be displayed
        return [malicious, undetected, unsupported, total], vend_mal, info, vendors
    else:
        #if input was wrong return error
        return "error", 'error', 'error', 'error'

# make a new entry into the database with data given
def create(md5p, sha256p, fileTypep, fileSizep, fileNamesp, vendorNamesp,
           totalVendorsp, vendorsFlaggedp, maliciousp, whoFlaggedp):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute(
        """INSERT INTO virusHash (md5,sha256,fileType,fileSize,fileNames,vendorNames,totalVendors,vendorsFlagged,malicious,whoFlagged) VALUES (?,?,?,?,?,?,?,?,?,?)""",
    (md5p, sha256p, fileTypep, fileSizep, fileNamesp, vendorNamesp, totalVendorsp, vendorsFlaggedp, maliciousp, whoFlaggedp,))
    con.commit()

# returns a boolean if md5 exists in database or not
def md5Exists(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT EXISTS (SELECT 1 FROM virusHash WHERE md5 = (?))", (md5,))

    if (cur.fetchone()[0]==1):
        return True
    else:
        return False

def shaExists(sha256):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT EXISTS (SELECT 1 FROM virusHash WHERE sha256 = (?))", (sha256,))

    if (cur.fetchone()[0] == 1):
        return True
    else:
        return False

def getHash(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM virusHash WHERE md5 = (?)", (md5,))

    return cur.fetchone()

# returns sha256 data for given md5
def getSha(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT sha256 FROM virusHash WHERE md5 = (?)", (md5,))

    return cur.fetchone()[0]

def getmd5(sha):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT md5 FROM virusHash WHERE sha256 = (?)", (sha,))

    return cur.fetchone()[0]

# returns file type data for given md5
def getType(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT fileType FROM virusHash WHERE md5 = (?)", (md5,))

    return cur.fetchone()[0]

# returns size data in bytes for given md5
def getSize(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT fileSize FROM virusHash WHERE md5 = (?)", (md5,))

    return cur.fetchone()[0]

# returns other names for given md5
def getNames(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT fileNames FROM virusHash WHERE md5 = (?)", (md5,))

    return cur.fetchone()[0]

# returns string of vendor names for given md5
def getVendorNames(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT vendorNames FROM virusHash WHERE md5 = (?)", (md5,))

    return cur.fetchone()[0]

# returns # of total vendors recorded for given md5
def getVendorTotal(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT totalVendors FROM virusHash WHERE md5 = (?)", (md5,))

    return cur.fetchone()[0]

# returns # of flagged vendors for given md5
def getVendorFlagged(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT vendorsFlagged FROM virusHash WHERE md5 = (?)", (md5,))

    return cur.fetchone()[0]

# returns a boolean if given md5 is malicious
def getMalicous(md5):
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT malicious FROM virusHash WHERE md5 = (?)", (md5,))

    return cur.fetchone()[0]

# returns all entries in local database
def select_all():
    con = sqlite3.connect('localHashes.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM virusHash")

    rows = cur.fetchall()

    return rows

def apiAdd(info, results, vend_mal, vendors):
    #make sure all required information is in the right format
    md5 = str(info[1])
    sha256 = str(info[2])
    names = ",".join(info[3])
    size = int(info[0])
    type = str(info[6])
    if results[0]*3 > results[3]:
        malicious = 1
    else:
        malicious = 0
    total = int(results[3])
    vend = int(results[0])
    who = ",".join(vend_mal)
    vendor = ",".join(vendors)
    #make new entry to database after api call
    create(md5,sha256,type,size,names,vendor,total,vend,malicious,who)

def autoFillDB():
    counter = 0
    with open ("hashesh.txt", 'r') as hashes:
        while hashes:
            hash = hashes.readline()
            url = "https://www.virustotal.com/api/v3/files/" + hash
            # janna's api key
            headers = {"Accept": "application/json",
                       "x-apikey": ["a87976713abed5a705da638f951311df7cfac0db207885c14fca88696df2b598",
                       "14c2f2dc80480dd86c00ec8b1756cf503f1e122c16381930b91643a3cb474d4e",
                       "4ea24321e6e93aa4e19a1732d6348ed0bc67310ee85efe91e316d8072fba65c4",
                       "90216388980f115bb5af4f6f379806435b0cb36015fb6fd0cfe059e8db8be4f2"]}
            #a87976713abed5a705da638f951311df7cfac0db207885c14fca88696df2b598
            #14c2f2dc80480dd86c00ec8b1756cf503f1e122c16381930b91643a3cb474d4e
            #4ea24321e6e93aa4e19a1732d6348ed0bc67310ee85efe91e316d8072fba65c4
            #90216388980f115bb5af4f6f379806435b0cb36015fb6fd0cfe059e8db8be4f2
            # if api call successful load in json file
            new_header = {"Accept": "application/json",
                          "x-apikey": headers["x-apikey"][counter%4]}
            try:
                response = requests.get(url, headers=new_header).json()
            # if api call unsuccessful inform user
            except:
                return "Error communicating with the VirusTotal API."
            results, vend_mal, info, vendors = make_api_call(response)
            # use case for hash not found on virustotal search
            if results == "error":
                return render_template("not_found.html")
            # if hash found information will be returned
            # add hash to database
            # view results to the user
            else:
                apiAdd(info, results, vend_mal, vendors)
                time.sleep(6.25)
                counter +=1
            if counter == 1900:
                return None

def addUser(username=None, password=None, password_confirm=None,fname=None, lname=None, email=""):
    if not username:
        return "Username is required."
    if not password:
        return "Password is required."
    if not fname:
        return "First name is required."
    if not lname:
        return "Last name is required."
    if email:
        valid = validEmail(email)
        if not valid:
            return "Entered email is not valid."
    if password != password_confirm:
        return "Password confirmation not correct."
    taken = nameTaken(username)
    if taken:
        return "Username already taken."
    pswd = validPassword(password)
    if pswd:
        return pswd
    else:
        #hashing function being used only accepts input in bytes
        #after making sure the password is valid convert it to bytes
        pswd = bytes(password, 'utf-8')
        #once password is in bytes it can be hashed, for security
        enc_password = zlib.adler32(pswd)
        con = sqlite3.connect('localUsers.db')
        cur = con.cursor()
        cur.execute("""SELECT * FROM users ORDER BY userID DESC LIMIT 1""")
        total_users = cur.fetchone()[0]+1
        print("TOTAL USEERS", total_users)
        cur.execute("""INSERT INTO users (userID,firstName,lastName,email,username,password,history) VALUES (?,?,?,?,?,?,?)""",
            (total_users, fname, lname, email, username, enc_password, "",))
        con.commit()
        return log_in(username, password)

def nameTaken(username):
    con = sqlite3.connect('localUsers.db')
    cur = con.cursor()
    cur.execute("SELECT EXISTS (SELECT 1 FROM users WHERE username = (?))", (username,))

    if (cur.fetchone()[0] == 1):
        return True
    else:
        return False

def validEmail(email):
    valid_extensions = [".com", ".net", ".edu", ".org"]
    if "@" not in email:
        return False
    elif email[len(email)-4::] not in valid_extensions:
        return False
    return True

def validPassword(password):
    if len(password) < 9:
        return "Password needs to be at least 10 characters."
    num = "Password must contain a number."
    special = "Password must contain a special character."
    for letter in password:
        if letter in NUMBERS:
            num = False
        if letter in SPECIAL:
            special = False
    if num:
        return num
    if special:
        return special
    if password.lower() == password:
        return "Password must contain at least one upper case and one lower case letter."
    if password.upper() == password:
        return "Password must contain at least one upper case and one lower case letter."

def log_in(username, password):
    global current_user
    user = nameTaken(username)
    if user:
        con = sqlite3.connect('localUsers.db')
        cur = con.cursor()
        cur.execute("SELECT password FROM users WHERE username = (?)", (username,))

        pswd =  cur.fetchone()[0]
        password_bytes = bytes(password, 'utf-8')
        password_hash = zlib.adler32(password_bytes)
        if pswd == str(password_hash):
            current_user = username
            return "Login successful"
        else:
            return "Incorrect password."
    else:
        return "Incorrect username."

def update_history(username, search):
    con = sqlite3.connect('localUsers.db')
    cur = con.cursor()
    cur.execute("""SELECT history FROM users WHERE username = (?)""", (username,))
    history = cur.fetchone()[0]
    if search not in history:
        if history:
            new_history = history + ","+search
        else:
            new_history = search

        cur.execute("""UPDATE users SET history = (?) WHERE username = (?)""", (new_history, username,))
        con.commit()

def get_user(username):
    con = sqlite3.connect('localUsers.db')
    cur = con.cursor()
    cur.execute("""SELECT * FROM users WHERE username = (?)""", (username,))
    return cur.fetchone()

def change_password(old, new1, new2):
    if new1 != new2:
        return "Password confirmation not the same as entered  password."
    if old == new1:
        return "New password cannot be the same as old password."
    password  = validPassword(new1)
    if password:
        return "New "+password
    con = sqlite3.connect('localUsers.db')
    cur = con.cursor()
    cur.execute("""SELECT password FROM users WHERE username = (?)""", (current_user,))
    stored = cur.fetchone()[0]
    old = bytes(old,  "utf-8")
    if stored != str(zlib.adler32(old)):
        return "Current password incorrect."
    new = zlib.adler32(bytes(new1, 'utf-8'))
    cur.execute("""UPDATE users SET password = (?) WHERE username = (?)""", (new,current_user,))
    con.commit()
    return "Successfully updated password."

def add_email(email):
    if validEmail(email):
        con = sqlite3.connect('localUsers.db')
        cur = con.cursor()
        cur.execute("""UPDATE users SET email = (?) WHERE username = (?)""", (email,current_user,))
        con.commit()
        return "success"
    return "Invalid email."
