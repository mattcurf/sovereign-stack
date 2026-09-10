from waitress import serve


def application(environ, start_response):
    body = b"Hello, world! From Python.\n"
    start_response("200 OK", [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ])
    return [body]


if __name__ == "__main__":
    serve(application, host="0.0.0.0", port=8080, threads=2,
          max_request_header_size=8192, max_request_body_size=1048576)
