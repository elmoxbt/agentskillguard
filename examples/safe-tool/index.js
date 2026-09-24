// examples/safe-tool/index.js
//
// FIXTURE — a well-behaved price-oracle tool. No wallet access, no shell,
// no dynamic code loading, and its only network call targets a domain
// that's on the example policy's allowlist. Used to demonstrate a clean
// AgentSkillGuard ALLOW verdict.

async function getPrice(mint) {
  const res = await fetch('https://api.jup.ag/price?ids=' + mint);
  const data = await res.json();
  return data.data[mint].price;
}

module.exports = { getPrice };
