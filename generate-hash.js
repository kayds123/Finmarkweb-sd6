const bcrypt = require('bcryptjs');
const password = 'tineganda';

bcrypt.hash(password, 12, (err, hash) => {
  if (err) throw err;
  console.log('bcryptjs hash:', hash);
});