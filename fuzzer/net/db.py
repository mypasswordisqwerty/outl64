import sqlite3


class DB:
    _instance = None
    GET = 0
    POST = 1
    PUT = 2
    DELETE = 3

    JOB_DISABLED = 1

    CLIENT_RELOAD = 1
    CLIENT_UPDATE = 2

    ACTIVE_DELTA_MIN = 60

    def __init__(self):
        if not self.__class__._instance:
            self.__class__._instance = sqlite3.connect("fuzzer.sqlite")
            c = self.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS jobs(
                id INTEGER NOT NULL PRIMARY KEY,
                name VARCHAR,
                task VARCHAR,
                flags INTEGER NOT NULL DEFAULT 0
                );""")
            c.execute("""CREATE TABLE IF NOT EXISTS clients(
                id INTEGER NOT NULL PRIMARY KEY,
                name VARCHAR DEFAULT NULL,
                ip VARCHAR DEFAULT NULL,
                version VARCHAR DEFAULT NULL,
                job INTEGER DEFAULT NULL,
                flags INTEGER NOT NULL DEFAULT 0,
                progress VARCHAR DEFAULT NULL,
                online DATETIME DEFAULT NULL
                );""")
            c.close()
            self.commit()

    def cursor(self):
        return self.__class__._instance.cursor()

    def commit(self):
        return self.__class__._instance.commit()

    def select(self, query, params=None, fields=None):
        if params is None:
            params = ()
        elif not isinstance(params, (dict, tuple)):
            params = (params,)
        c = self.cursor()
        c.execute(query, params)
        res = []
        if not fields:
            res = c.fetchall()
        else:
            row = c.fetchone()
            if not row:
                return res
            if len(row) != len(fields):
                raise Exception("Wrong fields count in query: " + query)
            while row:
                r = {}
                for i, x in enumerate(fields):
                    r[x] = row[i]
                res += [r]
                row = c.fetchone()
        c.close()
        return res

    def execute(self, query, params):
        c = self.cursor()
        c.execute(query, params)
        c.close()
        self.commit()
        return c.lastrowid

    def activeJobs(self):
        return [x[0] for x in self.select("SELECT id FROM jobs WHERE flags & ? = 0 ORDER BY id;", DB.JOB_DISABLED)]

    def registerClient(self, data, ip):
        hid = data.get('hostId') or -1
        nm = data.get('hostName') or "unknown"
        qry = "SELECT id, flags FROM clients WHERE "
        if hid > 0:
            host = self.select(qry + "id=?;", hid)
        else:
            host = self.select(qry + "ip=?;", ip)
        if not host or len(host) == 0:
            # create nu host
            if hid > 0:
                self.execute("INSERT INTO clients(id, name, ip) VALUES(?, ?, ?);", (hid, nm, ip))
            else:
                hid = self.execute("INSERT INTO clients(name, ip) VALUES(?, ?);", (nm, ip))
            host = self.select(qry + "id=?;", hid)
        host = host[0] if len(host) > 0 else None
        if not host:
            raise Exception("Host not found: {} {} {}".format(hid, nm, ip))
        # set job
        jobs = self.activeJobs()
        job = None if len(jobs) == 0 else jobs[host[0] % len(jobs)]
        flags = host[1]
        flags &= ~DB.CLIENT_RELOAD
        flags &= ~DB.CLIENT_UPDATE
        self.execute("UPDATE clients SET name=?, ip=?, version=?, job=?, online=DATETIME('NOW'), flags=? WHERE id=?;",
                     (nm, ip, data.get("version"), job, flags, host[0]))
        if job is not None:
            task = self.select("SELECT task FROM jobs WHERE id=?;", job)
            task = None if not task or len(task) < 1 else task[0][0]
        else:
            task = None
        return {"hostId": host[0], "flags": flags, "task": task}

    def heartbeat(self, data):
        if not data.get('hostId'):
            return
        self.execute("UPDATE clients SET progress=?, online=DATETIME('NOW') WHERE id=?;",
                     (data.get('progress'), data['hostId']))
        host = self.select("SELECT flags FROM clients WHERE id=?;", data['hostId'])
        flags = 0
        if host and len(host) > 0:
            flags = host[0][0]
        else:
            flags = DB.CLIENT_RELOAD
        return {'flags': flags}

    def reloadClients(self, job=None):
        if job is not None:
            self.execute("UPDATE clients SET flags=? WHERE job=?;", (DB.CLIENT_RELOAD, job))
            return
        jobs = self.activeJobs()
        for c in self.select("SELECT id, job FROM clients;"):
            job = None if len(jobs) == 0 else jobs[c[0] % len(jobs)]
            if job != c[1]:
                self.execute("UPDATE clients SET flags=? WHERE id=?;", (DB.CLIENT_RELOAD, c[0]))

    def restJob(self, method, data):
        flds = ["ID", "Task", "Name", "Flags"]
        qry = "SELECT id, task, name, flags FROM jobs"
        if method == DB.GET:
            return self.select(qry, fields=flds)
        elif method == DB.POST:
            rid = self.execute("INSERT INTO jobs(task, name) VALUES(?, ?);", (data['Task'], data['Name']))
            self.reloadClients()
            return self.select(qry + " WHERE id=?;", rid, flds)[0]
        elif method == DB.PUT:
            oldjob = self.select(qry + " WHERE id=?;", data['ID'], flds)[0]
            self.execute("UPDATE jobs SET task=?, name=?, flags=? WHERE id=?;",
                         (data['Task'], data['Name'], data['Flags'], data['ID']))
            if oldjob['Task'] != data['Task'] or str(oldjob['Flags']) != str(data['Flags']):
                self.reloadClients(data['ID'])
            return self.select(qry + " WHERE id=?;", data['ID'], flds)[0]
        elif method == DB.DELETE:
            self.execute("DELETE FROM jobs WHERE id=?;", data['ID'])
            self.reloadClients()
            return {}
        else:
            raise Exception("Unknown method: " + str(method))

    def restClient(self, method, data):
        flds = ["ID", "Name", "Ver", "IP", "Job", "Progress", "State", "Online", "Active"]
        qry = """SELECT c.id, c.name, c.version, c.ip, j.name, c.progress, c.flags, c.online,
            CASE WHEN CAST((JULIANDAY() - JULIANDAY(c.online)) * 24 * 60 AS INTEGER)>{} THEN 0 ELSE 1 END AS active
            FROM clients c LEFT JOIN jobs j ON j.id=c.job""".format(DB.ACTIVE_DELTA_MIN)
        if method == DB.GET:
            return self.select(qry, fields=flds)
        elif method == DB.PUT:
            if (data['ID'] == 'all'):
                self.execute("UPDATE clients SET flags=?;", data['State'])
                return {}
            else:
                self.execute("UPDATE clients SET flags=? WHERE id=?;", (data['State'], data['ID']))
            return self.select(qry + " WHERE c.id=?;", data['ID'], flds)[0]
        elif method == DB.DELETE:
            self.execute("DELETE FROM clients WHERE id=?;", data['ID'])
            return {}
        else:
            raise Exception("Unknown method: " + str(method))

    def onlineReport(self):
        cnt = self.select("SELECT COUNT(id) FROM clients;")[0][0]
        qry = """SELECT id, name FROM clients WHERE
            CAST((JULIANDAY() - JULIANDAY(online)) * 24 * 60 AS INTEGER)>?;"""
        offline = {}
        for x in self.select(qry, DB.ACTIVE_DELTA_MIN):
            offline[x[0]] = x[1]
        ret = "{}/{} hosts online".format(cnt - len(offline), cnt)
        if len(offline) > 0:
            ret += "\n{} hosts offline: {}".format(len(offline), str(offline))
        return ret
