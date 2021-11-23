from flask import Flask , render_template , request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pymysql
import os
import logging
import time
import datetime
import sys
import pipes
from flask import Flask, Response, redirect, session, abort,flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from werkzeug.utils import secure_filename






app = Flask(__name__)



limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "500 per hour"]
)

logging.basicConfig(filename='app.log', level=logging.DEBUG)


app.config.update(
    SECRET_KEY = "hamed_hfaz_Developer"
)

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):

    def __init__(self, id):
        self.id = id

    def __repr__(self):
        return "%d" % (self.id)



user = User(0)


@app.route("/")
def login():
    return render_template("login.html")

@app.route("/menu")
@login_required
def loogin():
    return redirect("/login.html")

@app.route("/" , methods=["POST"])
@limiter.limit("10 per minutes")
def loggin():
    username = request.form["username"]
    password = request.form["password"]
    if username == "hamed" and password =="102030102030":
        #time.sleep(5)
        return render_template("clamav.html")
    else:
        return redirect("login.html")



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return Response('<p>Logged out</p>')



@app.errorhandler(401)
def page_not_found(e):
    return Response('<p>Login failed</p>')


@login_manager.user_loader
def load_user(userid):
    return User(userid)


#AntiVirus


@app.route("/menu/antivirus")
def anti():
    return render_template("clamav.html")

@app.route("/menu/antivirus/scan" , methods=["POST"])
def scan():
    command = os.popen("clamscan -r --remove /home")
    read = command.read()
    return render_template("clamav.html", scan_results=read)

@app.route("/menu/antivirus/remove" , methods=["POST"])
def remove():
    command = os.popen("clamscan -r --remove /home")
    read = command.read()
    return render_template("clamav.html" , remove_results=read)



@app.route("/menu/antivirus/update", methods=["POST"])
def update():
    command = os.popen("freshclam")
    read = command.read()
    return render_template("clamav.html" ,update=read)



@app.route("/menu/antivirus/Qurantine" , methods=["POST"])
def quarantine():
    command=os.popen("clamscan -r --move /home/clamav/Quarantine")
    return Response("OK")






#antisheller


@app.route("/menu/antisheller")
def antisheller():
    return render_template("maldet.html")

@app.route("/menu/antisheller/scan" , methods=["POST"])
def antisheler_scan():
    scan = os.popen("maldet -a /home")
    read  = scan.read()
    return render_template("maldet.html" , shellerscan=read)


@app.route("/menu/antisheller/update" , methods=["POST"])
def antisheller_update():
    update = os.popen("maldet --update-ver")
    read = update.read()
    return render_template("maldet.html" , updatesheller=read)

@app.route("/menu/antisheller/report", methods=["POST"])
def report_sheller():
    repo = os.popen("maldet -report")
    read = repo.read()
    return render_template("maldet.html" , report=read)





@app.route("/menu/antirootkit")
def Rootkit_Hunter():
    return render_template("Rootkit_hunter.html")


@app.route("/menu/antirootkit/update" , methods=["POST"])
def update_rootkit():
    command = os.popen("rkhunter --update") # For Version Update
    scan = command.read()
    return render_template("Rootkit_hunter.html",update_Version=scan)




@app.route("/menu/antirootkit/fsystemupdate" , methods=["POST"])
def Filesystem_update():
    command = os.popen("rkhunter --propupd") # for updatinf Filesystems and files in Directory
    result=command.read()
    return render_template("Rootkit_hunter.html" , fupdate=result)



@app.route("/menu/antirootkit/scan" , methods=["POST"])
def RootKitscan():
    command = os.popen("rkhunter --check")  # For Real Scan
    scan = command.read()
    return render_template("Rootkit_hunter.html" , hunterscan=scan)





@app.route("/menu/antirootkit/chechconfig" , methods=["POST"])
def checkconfig():
    command = os.popne("sudo rkhunter -C")
    scan  = command.read()
    return render_template("Rootkit_hunter.html" , chech_result = checkconfig)


@app.route("/menu/firewall")
def firewall():
    return render_template("iptable.html")

@app.route("/menu/firewall/dhcpout" , methods=["POST"]) #close Output pinf of server
def dhcp_out():
    try:
        output_ping=os.popen("sudo ptables -A OUTPUT -p icmp -j REJECT")
        read = output_ping.read()
        return Response("<h1>Ok<h1>")
    except:
        return Response("Error on Closing External ping")

@app.route("/menu/firewall/dhcpin" , methods=["POST"])
def dhcpin():
    try:
        input_ping=os.popen("sudo sudo iptables -A INPUT -p icmp -j REJECT")
        read_input = input_ping.read()
        return Response("<h1>Ok<h1>")
    except:
        return Response("Error on closing Internal Ping")

@app.route("/menu/firewall/deldhcpout" , methods=["POST"])
def del_pingout():
    try:
        command = os.popen("sudo iptables -D OUTPUT -p icmp -j REJECT")
        op_command = command.read()
        return Response("<h1>OK<h1>")
    except:
        return Response("Error on Delete output icmp rule")



@app.route("/menu/firewall/deldhcpin" , methods=["POST"])
def del_pingin():
    try:
        command = os.popen("sudo iptables -D INPUT -p icmp -j REJECT")
        read_p = command.read()
        return Response("<h1>OK<h1>")
    except:
        return Response("Error on Delete input icmp rule")

@app.route("/menu/firewall/closeport" , methods=["POST"])
def port_close():
    port1 = request.form["port1"]
    port2 = request.form["port2"]
    port3 = request.form["port3"]
    port4 = request.form["port4"]
    port5 = request.form["port5"]
    port6 = request.form["port6"]
    port7 = request.form["port7"]
    port8 = request.form["port8"]
    port9 = request.form["port9"]
    port10= request.form["port10"]
    port11 = request.form["port11"]
    port12 = request.form["port12"]
    port13 = request.form["port13"]
    port14 = request.form["port14"]
    port15 = request.form["port15"]
    port16 = request.form["port16"]
    port17 = request.form["port17"]
    port18 = request.form["port18"]
    port19 = request.form["port19"]
    port20 = request.form["port20"]


    list = [port1,port2,port3,port4,port5,port6,port7,port8,port9,port10,port11,port12,port13,port14,port15,port16,port17,port18,port19,port20]

    for port in list:
        if port not in list:
            os.popen("sudo iptables -t nat -A POSTROUTIN -o eth0 -p tcp --dports {} -j DROP".format(port))
    return Response("<h1>OK<h1>")



@app.route("/menu/firewall/closeip" , methods=["POST"])
def ddos():
    ip1 = request.form["ip1"]
    ip2 = request.form["ip2"]
    ip3 = request.form["ip3"]
    ip4 = request.form["ip4"]
    ip5 = request.form["ip5"]
    ip6 = request.form["ip6"]
    ip7 = request.form["ip7"]
    ip8 = request.form["ip8"]
    ip9 = request.form["ip9"]
    ip10 = request.form["ip10"]
    ip11 = request.form["ip11"]
    ip12 = request.form["ip12"]
    ip13 = request.form["ip13"]
    ip14 = request.form["ip14"]
    ip15 = request.form["ip15"]
    ip16 = request.form["ip16"]
    ip17 = request.form["ip17"]
    ip18 = request.form["ip18"]
    ip19 = request.form["ip19"]
    ip20 = request.form["ip20"]


    list = [ip1,ip2,ip3,ip4,ip5,ip6,ip7,ip8,ip9,ip10,ip11,ip12,ip13,ip14,ip15,ip16,ip17,ip18,ip19,ip20]

    for port in list:
        if port not in list:
            os.popen(" sudo iptables -A INPUT -s {} -j DROP".format(port))
    return Response("<h1>OK<h1>")




@app.route("/menu/firewall/nmap" , methods=["POST"])
def nmap():
    os.popen("sudo iptables -A FORWARD -p tcp --tcp-flags SYN,AC,FIN,RST RST -m limit --limit 1/s -j ACCEPT")
    return Response("<h1>Nmap Scaning is Closed<h1>")





#System Backup



@app.route("/menu/backup")
def backup():
    return render_template("backup.html")


@app.route("/menu/backup/file" , methods=["POST"])
def file_backup():
    name = request.form["name"]
    filename = "{}.tar.gz".format(name)
    filedir = request.form["savedir"]
    command = os.popen("tar cfvz {} {}".format(filename,filedir))
    return Response("<h1>Done<h1>")

@app.route("/menu/backup/dir" , methods=["POST"])
def filebackup():
    name = request.form["name"]
    filename = "{}.tar.gz".format(name)
    dir = request.form["savedir"]
    command = os.popen("tar cfvz {} {}".format(filename,dir))
    return Response("<h1>Done<h1>")




#show tar file interior
@app.route("/menu/backup/fileinit" , methods=["POST"])
def file_init():
    file_name = request.files['file']
    command = os.popen(f'tar tf {file_name}')
    return render_template("file_interior.html")    
    
# Mysql Backup


@app.route("/menu/backup/mysql")
def mysql_backup():
    return render_template("backup.html")



@app.route("/menu/backup/mysql")
def backup_all_databases():
    databasename = request.form["databasename"]
    con = pymysql.connect(host='localhost',
                          user='root',
                          passwd='102030',
                          db='{}'.format(databasename))
    cur = con.cursor()

    cur.execute("SHOW TABLES")
    data = ""
    tables = []
    for table in cur.fetchall():
        tables.append(table[0])

    for table in tables:
        data += "DROP TABLE IF EXISTS `" + str(table) + "`;"

        cur.execute("SHOW CREATE TABLE `" + str(table) + "`;")
        data += "\n" + str(cur.fetchone()[1]) + ";\n\n"

        cur.execute("SELECT * FROM `" + str(table) + "`;")
        for row in cur.fetchall():
            data += "INSERT INTO `" + str(table) + "` VALUES("
            first = True
            for field in row:
                if not first:
                    data += ', '
                data += '"' + str(field) + '"'
                first = False


            data += ");\n"
        data += "\n\n"

    now = datetime.datetime.now()
    filename = str(os.getenv("HOME")) + "/backup_" + now.strftime("%Y-%m-%d_%H:%M") + ".sql"

    FILE = open(filename,"w")
    FILE.writelines(data)
    FILE.close()
    return render_template("success.html")




# @app.route("/menu/Flare")
# def hashcal():
#     return render_template("hash_calculator.html")
#
# @app.route("/menu/Flare" , methods=["POST"])
# def hashcalculator():



@app.route("/setting")
def setting():
    
    return render_template("setting.html")

@app.route("/setting" , methods=["POST"])
def main_setting():
    pass



"""When you want to backup from Linux Systems,its Better to backup this directories:
/home /etc /opt /root /usr / var """

"""Commnds for backup in Linux Systes are: tar & rsync & dd & cpio """



"""mt command is for tape and device of tape are st and st* or nst like mt /dev/st0 mt /dev/nst0-7"""


@app.route("/menu/tape")
def tape():
    return render_template("tape.html")


@app.route("/menu/tape/status")
def tape_status():
    #first Device is st0 mt -f /dev/st0 OPERATION [count][arg]
    command = os.popen("mt -f /dev/st0 status")
    read = command.read()
    return render_template("tape.html" , status=read)
    
@app.route("/menu/tape/erase")
def tape_status_erase():
    #first Device is st0 mt -f /dev/st0 erase [count][arg]
    command = os.popen("mt -f /dev/st0 erase")
    read = command.read()
    return render_template("tape.html" , erase=read)
    
    
    
    
@app.route("/menu/tape/forward")
def tape_status_forward():
    #first Device is st0 mt -f /dev/st0 fsf [count][arg]
    forward = request.form["forward"]
    command = os.popen(f"mt -f /dev/st0 fsf {forward}")
    read = command.read()
    return render_template("tape.html", forward=read)



@app.route("/menu/tape/backward")
def tape_status_backward():
    #first Device is st0 mt -f /dev/st0 bsf [count][arg]
    backward = request.form["backward"]
    command = os.popen(f"mt -f /dev/st0 bsf {backward}")
    read = command.read()
    return render_template("tape.html" , backward=read)


@app.route("/menu/tape/tell")
def tape_status_tell():
    #first Device is st0 mt -f /dev/st0 tell [count][arg]
    os.popen("mt -f /dev/st0")
    
    
@app.route("/menu/tape/eod")
def tape_status_eod():
    #first Device is st0 mt -f /dev/st0 eod [count][arg]
    os.popen("mt -f /dev/st0")
    
    
    
@app.route("/menu/tape/rewind")
def tape_status_rewind():
    #first Device is st0 mt -f /dev/st0 rewind [count][arg]
    os.popen("mt -f /dev/st0 rewind")    
    
    
    
@app.route("/menu/tape/eject")
def tape_status_eject():
    #first Device is st0 mt -f /dev/st0 OPERATION [count][arg]
    os.popen("mt -f /dev/st0")
    


    
    
    
@app.route("/menu/tape/backup" , methods=["POST"])
def tape_backup():
    which_disc=request.form["disc"]
    dir = request.form["directory"]
    location = request.form["location"]
    command_erase= os.popen(f"mt -f /dev/{which_disc} erase") 
    command_forward= os.popem(f"mt -f /dev/{which_disc} fsf {location}")
    command_backward= os.popen(f"mt -f /dev/{which_disc} bsf {location}")
    command_backup= os.popen(f"tar cf /dev/{which_disc} {dir}")
    
    

    
@app.route("/menu/tape/recover" , methods=["POST"])
def recover_data():
     which_disc=request.form["disc"]
     dir = request.form["directory"]
     location = request.form["location"]
     command_backup = os.popem(f"mt -f /dev/{which_disc} {dir}")

    
    
    
    
if __name__ == "__main__":


    app.run("0.0.0.0", "8080")
