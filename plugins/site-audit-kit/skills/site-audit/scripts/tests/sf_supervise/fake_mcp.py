"""Fake Screaming Frog MCP server (streamable HTTP, JSON-RPC, SSE replies, Mcp-Session-Id) and a
fake health endpoint, for sf_supervise tests. Never talks to the real Screaming Frog server.

Response shapes copied from the real seospider-mcp-server 1.0.0 (SF 24.3) as recorded in Run 1:
  sf_crawl_progress -> {"apiProgress":{...},"crawlProgress":{"active","completed","percentComplete",
                        "waiting"},"databaseId":..,"postCrawlAnalysisProgress":{...},"stateName":..}
  sf_list_crawls    -> [{"instanceDirName","url","spiderMode","crawlName","urlsCrawled",...}]
  busy              -> result.isError with "Tool error: IllegalStateException: Tool cannot be called
                       currently. Please check the state of the Spider"
  expired session   -> HTTP 404 {"jsonRpcError":{"message":"Session not found: <sid>"}}
"""
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BUSY_TEXTS = ["Tool error: Spider busy",
              "Tool error: IllegalStateException: Tool cannot be called currently. Please check the state of the Spider"]


class Scenario:
    def __init__(self, base_dir, **kw):
        self.base_dir = base_dir
        self.initial = kw.get("initial", "idle")     # idle | active | paused
        self.active_polls = kw.get("active_polls", 3)  # None = crawl forever
        self.analysis_step = kw.get("analysis_step", 50)
        self.pause_delay = kw.get("pause_delay", 0)    # progress calls after pause before it takes
        self.busy_after_load = kw.get("busy_after_load", 0)
        self.expire_every = kw.get("expire_every", 0)  # expire the session every N tool calls
        self.never_starts = kw.get("never_starts", False)
        self.foreign_after = kw.get("foreign_after")   # after N active polls, another crawl is running
        self.foreign_name = kw.get("foreign_name", "someone-else")  # that crawl's name ("t1" = same name)
        self.foreign_preexisting = kw.get("foreign_preexisting", False)  # its id is listed before our start
        self.pause_never = kw.get("pause_never", False)  # sf_pause_crawl answers OK but never takes
        self.export_delay = kw.get("export_delay", 0)  # seconds the export call takes (outside the lock)
        self.hide_mine_after_finish = kw.get("hide_mine_after_finish", False)  # our id vanishes from the list
        self.same_name_old = kw.get("same_name_old", False)  # an older stored crawl also named "t1"
        self.after_load_active = kw.get("after_load_active", 0)  # progress polls showing active after a load
        # sf_crawl reply trouble: "drop" (crawl starts, connection closed with no reply), "garbage"
        # (crawl starts, 200 with a non-JSON body), "drop-nostart" (nothing starts, no reply),
        # "drop-foreign" (no reply; a crawl that is not ours becomes the running one)
        self.crawl_reply = kw.get("crawl_reply")
        # sf_export_seo_element_urls trouble: "partial-error" (writes a partial file, then a tool
        # error), "partial-garbage" (writes it, then a non-JSON 200 reply), "drop" (writes it, then
        # the connection closes with no reply)
        self.export_fail = kw.get("export_fail")
        # progress polls after the export call during which the spider stays busy and the export
        # keeps appending raw lines (None = forever); 0 = the export is finished when it returns
        self.export_busy_polls = kw.get("export_busy_polls", 0)
        self.api_message = kw.get("api_message", "All APIs / URL Inspection: 5 / 5")
        self.export_writing = None  # the file the export is still writing, if any
        self.export_busy_seen = 0
        self.huge_reply = kw.get("huge_reply", 0)  # bytes of padding in every tools/call reply
        self.finish_with_db = kw.get("finish_with_db")  # databaseId reported once the crawl is idle
        self.export_started = threading.Event()
        self.load_active_left = 0
        self.lock = threading.RLock()
        self.log = []          # every JSON-RPC request: (method, tool or None, arguments)
        self.inits = 0
        self.sessions = set()
        self.calls_since_init = 0
        self.old_db = "old-0000"
        if self.initial == "idle":
            self.phase, self.db = "idle", self.old_db
        elif self.initial == "active":
            self.phase, self.db = "active", "someone-elses-crawl"
        else:
            self.phase, self.db = "paused", "someone-elses-crawl"
        self.crawl_name = None
        self.my_db = None
        self.foreign_db = "foreign-crawl-db"
        self.completed = 0
        self.ticks = 0
        self.analysis = 100
        self.pause_pending = None
        self.busy_left = 0
        self.pause_calls = 0

    def tools(self):
        return [l[1] for l in self.log if l[0] == "tools/call"]

    # -- tool implementations
    def progress(self):
        if self.export_writing is not None:
            if self.export_busy_polls is not None and self.export_busy_seen >= self.export_busy_polls:
                self.export_writing = None
            else:
                self.export_busy_seen += 1
                with open(self.export_writing, "a") as f:
                    f.write(json.dumps({"Address": "https://www.example.com/late?token=LATESECRET77"}) + "\n")
                return {"apiProgress": {"message": "Exporting", "percentComplete": 50},
                        "crawlProgress": {"active": 0, "completed": self.completed},
                        "databaseId": self.db, "postCrawlAnalysisProgress": {"percentComplete": 100},
                        "stateName": "SpiderActiveState"}
        if self.load_active_left > 0:
            self.load_active_left -= 1
            return {"apiProgress": {}, "crawlProgress": {"active": 1, "completed": self.completed},
                    "databaseId": self.db, "postCrawlAnalysisProgress": {"percentComplete": 100},
                    "stateName": "SpiderActiveState"}
        if self.phase == "active" and not self.never_starts:
            self.ticks += 1
            self.completed += 10
            if self.foreign_after is not None and self.ticks > self.foreign_after:
                self.db = self.foreign_db
            if self.active_polls is not None and self.ticks >= self.active_polls:
                self.phase, self.analysis = "analysis", 0
        elif self.phase == "analysis":
            self.analysis = min(100, self.analysis + self.analysis_step)
            if self.analysis >= 100:
                self.phase = "idle"
                if self.finish_with_db:
                    self.db = self.finish_with_db
        if self.pause_pending is not None:
            if self.pause_pending <= 0:
                self.phase, self.pause_pending = "paused", None
            else:
                self.pause_pending -= 1
        state = {"idle": "SpiderCrawlIdleState", "active": "SpiderActiveState",
                 "analysis": "CrawlAnalysisSpiderState:(Task - AggregatedProgressableTask)",
                 "paused": "SpiderPausedState", "starting": "SpiderCrawlIdleState"}[self.phase]
        return {"apiProgress": {"message": self.api_message, "percentComplete": 100},
                "crawlProgress": {"active": 3 if self.phase == "active" else 0, "completed": self.completed,
                                  "percentComplete": 50 if self.phase == "active" else 100,
                                  "waiting": 100 if self.phase == "active" else 0},
                "databaseId": self.db,
                "postCrawlAnalysisProgress": {"message": "", "percentComplete": self.analysis},
                "stateName": state}

    def call(self, name, args):
        """Return (text, is_error)."""
        if name == "sf_crawl_progress":
            return json.dumps(self.progress()), False
        if name == "sf_crawl":
            if self.phase in ("active", "analysis"):
                return "Tool error: IllegalStateException: Tool cannot be called currently. Please check the state of the Spider", True
            cfg = args.get("config_path", "")
            if not os.path.isabs(cfg):
                return f"Tool error: NoSuchFileException: {cfg}", True
            if self.crawl_reply == "drop-nostart":
                return None, False
            if self.crawl_reply == "drop-foreign":
                self.db, self.phase, self.ticks = self.foreign_db, "active", 0
                self.foreign_after = 0
                return None, False
            self.crawl_name = args.get("crawl_name")
            self.db = self.my_db = "db-" + uuid.uuid4().hex[:8]
            self.phase = "starting" if self.never_starts else "active"
            self.ticks, self.completed = 0, 0
            if self.crawl_reply in ("drop", "garbage"):
                return None, False
            return "Crawl started", False
        if name == "sf_pause_crawl":
            self.pause_calls += 1
            if (self.phase == "active" or self.phase == "analysis") and not self.pause_never:
                self.pause_pending = self.pause_delay
            return "Crawl paused", False
        if name == "sf_list_crawls":
            out = []
            finished = self.phase == "idle" and self.my_db is not None
            if self.crawl_name and self.my_db and not (self.hide_mine_after_finish and finished):
                out.append({"instanceDirName": self.my_db,
                            "url": "https://www.example.com/", "spiderMode": "Spider",
                            "crawlName": self.crawl_name, "urlsCrawled": self.completed,
                            "percentageComplete": 100.0, "time": "Jan 1, 2030", "projectVersion": "24.3"})
            if self.db == self.foreign_db or self.foreign_preexisting:
                out.insert(0, {"instanceDirName": self.foreign_db, "crawlName": self.foreign_name, "url": "x"})
            out.append({"instanceDirName": self.old_db,
                        "crawlName": "t1" if self.same_name_old else "older-crawl", "url": "x",
                        "spiderMode": "Spider", "urlsCrawled": 5, "percentageComplete": 100.0})
            return json.dumps(out), False
        if name == "sf_load_crawl":
            self.busy_left = self.busy_after_load
            self.load_active_left = self.after_load_active
            return f"Loaded crawl {args.get('crawl_id')}", False
        if name == "sf_export_seo_element_urls":
            if self.busy_left > 0:
                self.busy_left -= 1
                return BUSY_TEXTS[self.busy_left % 2], True
            fp = args.get("file_path") or ""
            if os.path.isabs(fp):
                return f"Tool error: SecurityException: absolute path not allowed: {fp}", True
            dest = os.path.join(self.base_dir, fp)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w") as f:
                f.write(json.dumps({"Address": "https://www.example.com/a/"}) + "\n")
                f.write(json.dumps({"Address": "https://www.example.com/reset?token=SECRETVALUE123&lang=en"}) + "\n")
            os.chmod(dest, 0o644)
            if self.export_busy_polls is None or self.export_busy_polls > 0:
                self.export_writing, self.export_busy_seen = dest, 0
            if self.export_fail == "drop":
                return None, False
            if self.export_fail == "partial-error":
                return "Tool error: IOException: export interrupted", True
            if self.export_fail == "partial-garbage":
                return None, False
            return json.dumps({"format": "NDJSON", "path": dest, "total_records": 2,
                               "sample": "{\"Address\":\"https://www.example.com/a/\"}"}), False
        return f"Tool error: unknown tool {name}", True


def make_handler(sc):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, obj, sid=None, sse=True):
            body = ("event: message\ndata: " + json.dumps(obj) + "\n\n") if sse else json.dumps(obj)
            raw = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
            if sid:
                self.send_header("Mcp-Session-Id", sid)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(n) or b"{}")
            meth = req.get("method")
            sid = self.headers.get("Mcp-Session-Id")
            with sc.lock:
                p = req.get("params") or {}
                sc.log.append((meth, p.get("name"), p.get("arguments")))
                if meth == "initialize":
                    sc.inits += 1
                    s = uuid.uuid4().hex
                    sc.sessions.add(s)
                    sc.calls_since_init = 0
                    return self.send(200, {"jsonrpc": "2.0", "id": req["id"], "result": {
                        "protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake-seospider-mcp", "version": "0"}}}, sid=s)
                if sid not in sc.sessions:
                    sc.log[-1] = ("rejected-session", p.get("name"), p.get("arguments"))
                    return self.send(404, {"jsonRpcError": {"code": -32603, "message": f"Session not found: {sid}"},
                                           "message": f"Session not found: {sid}"}, sse=False)
                if meth == "notifications/initialized":
                    self.send_response(202)
                    self.end_headers()
                    return
                if meth == "tools/list":
                    return self.send(200, {"jsonrpc": "2.0", "id": req["id"], "result": {"tools": []}})
                if meth == "tools/call":
                    if sc.expire_every and sc.calls_since_init >= sc.expire_every:
                        sc.sessions.discard(sid)
                        sc.log[-1] = ("rejected-session", p.get("name"), p.get("arguments"))
                        return self.send(404, {"jsonRpcError": {"code": -32603, "message": f"Session not found: {sid}"}},
                                         sse=False)
                    sc.calls_since_init += 1
                    if p.get("name") == "sf_export_seo_element_urls" and sc.export_delay:
                        sc.export_started.set()
                        sc.lock.release()
                        try:
                            time.sleep(sc.export_delay)
                        finally:
                            sc.lock.acquire()
                    text, err = sc.call(p.get("name"), p.get("arguments") or {})
                    if text is None:
                        if p.get("name") == "sf_crawl":
                            mode = sc.crawl_reply
                        elif p.get("name") == "sf_export_seo_element_urls" and sc.export_fail == "drop":
                            mode = "drop"
                        else:
                            mode = "garbage"
                        if mode == "garbage":
                            raw = b"this is not JSON"
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(raw)))
                            self.end_headers()
                            self.wfile.write(raw)
                        self.close_connection = True  # "drop": no reply at all
                        return
                    res = {"jsonrpc": "2.0", "id": req["id"], "result": {
                        "content": [{"type": "text", "text": text}], "isError": err}}
                    if sc.huge_reply:
                        res["padding"] = "x" * sc.huge_reply
                    return self.send(200, res)
                return self.send(400, {"jsonrpc": "2.0", "id": req.get("id"),
                                       "error": {"code": -32601, "message": "method not found"}})
    return H


class Health:
    def __init__(self):
        self.status = {"/home": 200, "/blog": 200}
        self.hits = 0


def make_health_handler(h):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            h.hits += 1
            path = self.path.split("?")[0]
            if path == "/trickle":  # 200 headers, then one byte every 0.2 s for 20 s
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.2)
                except OSError:
                    pass
                return
            code = h.status.get(path, 404)
            body = b"ok" if code == 200 else b"fail"
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return H


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv
