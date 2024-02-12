# Command to run mongo container
docker run -v jwtMongoData:/data/db -p 27017:27017 -d --name jwtMongo mongo