FROM node:24-bookworm@sha256:6449e19d8184d84062525b6a7524def03146c2cb04a7f08b076680d0e8e4240a
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && python3 --version
# Official SDK asset validation/chmod only; no runtime process or model is started.
RUN node --input-type=module -e "import { ensureRuntimeBundle } from './node_modules/@github/copilot-sdk/dist/runtimeArtifacts.js'; await ensureRuntimeBundle('1.0.98');"
COPY __init__.py snapshot.py broker.py broker_stdio.py sdk-tools.mjs client-options.mjs native-probe.mjs ./repo_wide_readonly/
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 HOME=/tmp/home COPILOT_HOME=/tmp/home/.copilot
USER 65534:65534
ENTRYPOINT ["node", "/app/repo_wide_readonly/native-probe.mjs"]
