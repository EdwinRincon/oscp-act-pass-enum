# osint/report/console.py
import sys
import time

RESET = "\033[0m"
STYLES = {"green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m",
          "bold": "\033[1m", "dim": "\033[2m"}
GOOD = {"open", "present", "ok"}
BAD = {"closed", "missing", "failed", "exposed"}


class Console:
    def __init__(self, color=None, stream=None):
        self.stream = stream or sys.stdout
        self.color = self.stream.isatty() if color is None else color

    def paint(self, text, style):
        return f"{STYLES[style]}{text}{RESET}" if self.color else text

    def line(self, text=""):
        print(text, file=self.stream, flush=True)

    def banner(self, tool, target, mode=""):
        stamp = time.strftime("%Y-%m-%d %H:%M %Z")
        extra = f" [{mode}]" if mode else ""
        self.line(f"Starting {tool} ( {target} ){extra} at {stamp}")
        self.line()

    def table(self, headers, rows, indent=2, max_width=60):
        cells = [[str(c) for c in r] for r in rows]
        widths = [len(h) for h in headers]
        for r in cells:
            for i, c in enumerate(r[:-1]):
                widths[i] = max(widths[i], min(len(c), max_width))
        pad = " " * indent

        def fmt(row, head=False):
            out = []
            for i, c in enumerate(row):
                last = i == len(row) - 1
                if not last and len(c) > widths[i]:
                    c = c[:widths[i] - 1] + "…"
                text = c if last else c.ljust(widths[i])
                if head:
                    text = self.paint(text, "bold")
                elif c.lower() in GOOD:
                    text = self.paint(text, "green")
                elif c.lower() in BAD:
                    text = self.paint(text, "red")
                out.append(text)
            return pad + "  ".join(out)

        self.line(fmt(headers, head=True))
        for r in cells:
            self.line(fmt(r))

    def module(self, res):
        tag = self.paint(f"[{res.phase.upper()}]", "bold")
        self.line(f"{tag} {res.name}  {self.paint(f'({res.elapsed:.1f}s)', 'dim')}")
        if res.source:
            conf = f" | confidence: {res.confidence}" if res.status == "ok" else ""
            self.line("  " + self.paint(f"source: {res.source}{conf}", "dim"))
        if res.status == "failed":
            self.line("  " + self.paint(f"! failed: {res.error}", "red"))
        elif res.status == "skipped":
            self.line("  " + self.paint(f"- skipped: {res.error}", "yellow"))
        elif not res.rows:
            self.line("  " + self.paint("(no data)", "dim"))
        else:
            self.table(res.headers, res.rows)
        self.line()

    def summary(self, results, elapsed):
        ok = sum(r.status == "ok" for r in results)
        failed = sum(r.status == "failed" for r in results)
        self.line(f"Done: {len(results)} modules, {ok} ok, {failed} failed "
                  f"in {elapsed:.1f}s")