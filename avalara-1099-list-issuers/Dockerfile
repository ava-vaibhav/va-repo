FROM denoland/deno:2.3.7
ENV NO_COLOR=true

EXPOSE 3000
WORKDIR /app

copy package.json package.json
RUN deno install

COPY . .

CMD ["run", "-A", "--unstable-sloppy-imports", "src/index.ts"]