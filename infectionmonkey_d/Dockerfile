FROM ubuntu:focal

COPY ./InfectionMonkey-v1.13.0.AppImage /etc/service/InfectionMonkey-v1.13.0.AppImage

RUN 	apt-get update && apt-get -y install \
		net-tools iproute2 iputils-ping telnet iperf

RUN 	chmod u+x /etc/service/InfectionMonkey-v1.13.0.AppImage

EXPOSE 5000

CMD ["/etc/service/InfectionMonkey-v1.13.0.AppImage", "--appimage-extract-and-run"]
