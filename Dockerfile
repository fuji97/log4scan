FROM python:3.10

WORKDIR /home/user

# copy the dependencies file to the working directory
COPY requirements.txt .

# install dependencies
RUN pip3 install -r requirements.txt

# copy the content of the local src directory to the working directory
COPY ./ .

ENTRYPOINT ["python", "log4shell-scanner.py" ]