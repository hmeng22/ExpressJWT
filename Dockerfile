FROM node:carbon

WORKDIR /app

COPY . /app

RUN npm install
RUN npm i -g pm2

EXPOSE 80

CMD ["npm", "start"]
