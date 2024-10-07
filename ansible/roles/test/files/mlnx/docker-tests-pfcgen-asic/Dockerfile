FROM python:3.9-bullseye

RUN mkdir -m 0755 -p /root/pkgs

COPY ./pkgs /root/pkgs
COPY ["install.sh", "start.sh", "pfc_gen.py", "pfc_gen_cpu.py", "/root/"]

RUN /root/install.sh
RUN echo "export PYTHONPATH=/usr/lib/python3/dist-packages/" >> /root/.bashrc

CMD ["/root/start.sh"]
