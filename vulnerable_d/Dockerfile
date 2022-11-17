FROM ubuntu:trusty
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN 	useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo ubuntu
RUN 	echo 'ubuntu:ubuntu' | chpasswd
USER 	ubuntu
WORKDIR /home/ubuntu

USER root
RUN 	apt-get update \
		&& apt-get -y install openssh-server telnet iperf

RUN 	sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
RUN 	mkdir /var/run/sshd
RUN 	bash -c 'install -m755 <(printf "#!/bin/sh\nexit 0") /usr/sbin/policy-rc.d'
RUN 	ex +'%s/^#\zeListenAddress/\1/g' -scwq /etc/ssh/sshd_config
RUN 	RUNLEVEL=1 dpkg-reconfigure openssh-server
RUN 	ssh-keygen -A -v
RUN 	update-rc.d ssh defaults

RUN 	ex +"%s/^%sudo.*$/%sudo ALL=(ALL:ALL) NOPASSWD:ALL/g" -scwq! /etc/sudoers
RUN 	sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
