const { Rsa } = require('./dist/index');

const rsa = new Rsa('./rsa-public.key', './rsa-private.key', true);

const data = 'h+tJowCpBEk8YNaVe8PPBWhlNhDU5YVkb8IBWMhyUnGGuAJ9olkxbQiZ8wHLlaFIuIuHj0F0lXhn77zOvpR0r+o/0MoRRwAU7Z5Vp6iw/bgeC2U/qkHCqpQJAlpg9ye3r3aJihPM6OznDgFbqgYU138v2EJB+8DC0q7KX388JNg=';
const decrypted = rsa.rsaDecrypt(data);

console.log(decrypted);