# Built by the GitHub Actions docker-build job.
# A local image build was not run on the authoring workstation.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN go build -o /out/ ./cmd/...

FROM debian:bookworm-slim
RUN useradd --create-home --uid 10001 zt
COPY --from=build /out/ /usr/local/bin/
USER zt
EXPOSE 8080
ENTRYPOINT ["control-plane"]
CMD ["health"]
