from osint.base import Module, ScanContext


class SecurityHeaders(Module):
    name = "HTTP security headers"
    phase = "active"

    def __init__(self, context: ScanContext):
        self.context = context

    def run(self, domain):
        from osint.security_headers import check_security_headers, report_rows

        timeout = self.context.options.get("timeout", 10)
        response, rows, leaks = check_security_headers(
            domain, timeout=timeout, client=self.context.client)
        headers, report = report_rows(response, rows, leaks)
        return self.result(headers, report)
