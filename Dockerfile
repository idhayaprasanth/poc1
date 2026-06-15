# =============================================================================
#  Vulnerability Risk Intelligence Dashboard — Docker image for DGX / Linux
# =============================================================================
#  Build:
#    docker build -t tui-dashboard .
#
#  Run (requires an interactive TTY):
#    docker run --rm -it \
#      --env-file .env \
#      -v "$(pwd)/security_dashboard/assets:/app/security_dashboard/assets" \
#      tui-dashboard
#
#  Notes:
#  • The container MUST be started with -it (interactive + pseudo-TTY) so that
#    curses can query terminal dimensions and render the UI.
#  • Mount the assets directory so the dashboard can read/write CSV data without
#    rebuilding the image every time.
#  • Pass secrets via --env-file .env (never bake .env into the image).
# =============================================================================

FROM python:3.11-slim

# ── System dependencies ───────────────────────────────────────────────────────
# libncursesw5-dev: wide-character ncurses needed for Unicode box-drawing chars
# locales / locales-all: ensures UTF-8 locale for Unicode rendering
RUN apt-get update && apt-get install -y --no-install-recommends \
        libncursesw5-dev \
        locales \
    && locale-gen en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

# ── Locale / terminal environment ─────────────────────────────────────────────
ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    TERM=xterm-256color \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /app

# ── Python dependencies ───────────────────────────────────────────────────────
# Copy the Linux-specific requirements file (excludes windows-curses)
COPY requirements-linux.txt ./requirements-linux.txt
RUN pip install --no-cache-dir -r requirements-linux.txt

# ── Application source ────────────────────────────────────────────────────────
# Copy everything except files listed in .dockerignore
COPY . .

# ── Debug log location ────────────────────────────────────────────────────────
# tui_ai_analysis.log is written to the project root at runtime.
# Optionally mount /app to persist logs: -v $(pwd)/logs:/app
VOLUME ["/app/security_dashboard/assets"]

# ── Entry point ───────────────────────────────────────────────────────────────
CMD ["python", "tui_dashboard.py"]
