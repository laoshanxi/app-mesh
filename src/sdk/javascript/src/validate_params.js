// validate_params.js

const validators = require("./validators");

function validate_params(schema) {
  return function (target, key, descriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function (...args) {
      const errors = [];
      const functionName = key; // Capture the function name

      Object.keys(schema).forEach((param, index) => {
        const value = args[index];
        const rules = schema[param];
        const paramErrors = [];

        rules.forEach((rule) => {
          const [validatorName, errorMessage] = Array.isArray(rule) ? rule : [rule, `Invalid ${param}`];
          const validator = validators[validatorName];
          // Skip validation if value is null
          if ((value === undefined || value === null) && validatorName !== "isOptional") {
          } else if (validator && !validator(value)) {
            paramErrors.push(errorMessage);
          }
        });

        if (rules.length === paramErrors.length) {
          Array.prototype.push.apply(errors, paramErrors);
        }
      });

      if (errors.length > 0) {
        throw new Error(`"${functionName}" parameter validation failed: ${errors.join(", ")}`);
      }

      return originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

module.exports = validate_params;
