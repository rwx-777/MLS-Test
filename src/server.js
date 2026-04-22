const { createApp } = require('./app');
const { config } = require('./config');

const app = createApp();

app.listen(config.port, () => {
  console.log(`MLS backend listening on ${config.port}`);
});
