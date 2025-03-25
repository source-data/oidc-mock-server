FROM node:10.15-alpine

WORKDIR /app

# Update packages in base image
RUN apk update && apk upgrade && apk add git

COPY . .

RUN npm install

# User 1000 is already provided in the base image (as 'node')

RUN chown -R node:node /app

USER 1000

ENV DEBUG="oidc-provider:*"
CMD [ "npm", "start" ]
