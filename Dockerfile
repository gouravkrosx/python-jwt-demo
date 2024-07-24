# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt /app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

ADD https://keploy-enterprise.s3.us-west-2.amazonaws.com/releases/latest/assets/freeze_time_arm64.so /lib/keploy/freeze_time_arm64.so

#set suitable permissions
RUN chmod +x /lib/keploy/freeze_time_arm64.so

# Set LD_PRELOAD environment variable to use freeze_time_arm64.so
ENV LD_PRELOAD=/lib/keploy/freeze_time_arm64.so

# Copy the rest of the current directory contents into the container at /app
COPY . /app

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Run app.py when the container launches
# ENV LD_PRELOAD=./freeze_time_arm64.so
# CMD ["sh", "-c", "LD_PRELOAD=./freeze_time.so flask run"]

CMD ["flask", "run"]

