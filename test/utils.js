module.exports.readOnly = (target, key, descriptor) => {
  return {
    ...descriptor,
    writable: false,
  };
}