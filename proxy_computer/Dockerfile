FROM golang:1.24.5

RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /app

COPY go.* ./

RUN go mod download

COPY . .

RUN go build -o main

EXPOSE 8080

CMD [ "./main" ]