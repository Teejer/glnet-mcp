# glnet-mcp -- MCP server for GL.iNet routers.
#
# Nothing here needs compiling: the server is pure Python over stdlib HTTP plus
# passlib for the BSD md5_crypt that the router's login handshake requires
# (Python 3.13 removed the stdlib `crypt` module).

FROM python:3.14-slim

# A non-root user exists so the image is safe to run without an explicit
# --user, but the launcher overrides this with your real uid/gid anyway so that
# the bind-mounted secret file is readable without granting group access.
RUN groupadd -g 10000 glnet \
 && useradd -m -u 10000 -g 10000 -s /usr/sbin/nologin glnet

WORKDIR /app

# Dependencies first so the layer survives edits to server.py.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py ./

USER 10000:10000

# The launcher stages the decrypted secret onto tmpfs and bind-mounts it here.
# Deliberately not an ENV: env vars are readable via `docker inspect`.
ENV GLNET_PASSWORD_FILE=/run/secrets/glnet.password \
    HOME=/tmp \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-u", "/app/server.py"]
