FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-crackq"
LABEL org.opencontainers.image.vendor="Cognis Digital"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/crackq"
LABEL org.opencontainers.image.licenses="MIT"
WORKDIR /work
COPY . .
RUN pip install --no-cache-dir -e ".[mcp,web]"
EXPOSE 8000
ENTRYPOINT ["crackq"]
CMD ["--help"]
