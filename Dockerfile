# FROM — which base image to build on top of
# Think of this as choosing your operating system + runtime.
# python:3.9-slim is a minimal Linux image with Python 3.9 pre-installed.
# We are deliberately using 3.9 (not the latest) because it has known
# CVEs that Trivy will find. This proves why base image choice
# is a security decision, not just a technical preference.
# slim means it excludes compilers and dev tools — smaller attack surface
# than the full python:3.9 image, but still has vulnerabilities.
FROM python:3.9-slim

# WORKDIR — sets the working directory inside the container
# All commands after this run from /app inside the container.
# If /app doesn't exist, Docker creates it automatically.
# Why /app? Convention. Could be anything, but /app is standard.
WORKDIR /app

# COPY requirements first — before copying the rest of the code.
# Why this order? Docker builds images in layers. Each instruction
# creates a new layer. Docker caches layers — if nothing changed
# in a layer, it reuses the cached version instead of rebuilding.
# requirements.txt changes rarely. app code changes constantly.
# By copying requirements first and installing them as a separate layer,
# Docker can cache the pip install layer. Next time you rebuild,
# if only app.py changed, Docker skips the pip install entirely.
# Reverse the order and every code change triggers a full reinstall.
COPY app/requirements.txt .

# RUN — executes a shell command during the image build.
# This installs Flask and its dependencies inside the container.
# --no-cache-dir tells pip not to store the download cache.
# Why? Cache files are useless in a container and just add image size,
# which means more bytes to scan, store, and transfer.
RUN pip install --no-cache-dir -r requirements.txt

# COPY the rest of the application code into the container.
# First dot = source on your Mac (the app/ folder contents)
# Second dot = destination inside container (/app, our WORKDIR)
COPY app/ .

# EXPOSE — documents which port the app listens on.
# This does NOT actually open the port — it's documentation only.
# The port is opened when you run the container with -p 5000:5000.
# Why document it? So other developers and tools know what to expect.
EXPOSE 5000

# CMD — the command that runs when the container starts.
# This is different from RUN. RUN happens at build time.
# CMD happens at runtime — every time someone starts this container.
# We run python with app.py. Note: no debug=True here in production,
# but our app.py still has debug mode on — Semgrep will flag this too.
CMD ["python", "app.py"]