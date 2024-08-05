// validators.js
const iso8601 = require("iso8601-duration");

const validators = {
  isValidName: (value) => {
    if (typeof value !== "string") {
      return false;
    }
    const trimmedValue = value.trim();
    // Check if it's a non-empty string after trimming
    if (trimmedValue === "") {
      return false;
    }

    // Check for valid characters
    // Allow alphanumeric characters, hyphen, underscore, period, and space
    // Disallow consecutive periods to prevent path traversal
    const validPathRegex = /^[a-zA-Z0-9-_. ]+$/;
    const consecutivePeriodsRegex = /\.\./;

    return validPathRegex.test(trimmedValue) && !consecutivePeriodsRegex.test(trimmedValue);
  },
  isValidString: (value) => typeof value === "string" && value.length > 0,
  isString: (value) => typeof value === "string",

  isFunction: (value) => typeof value === "function",

  isPositiveNumber: (value) => typeof value === "number" && value > 0,
  isNumber: (value) => typeof value === "number",
  isISO8601Duration: (value) => {
    try {
      iso8601.parse(value);
      return true;
    } catch (error) {
      return false;
    }
  },

  isTimeoutValue: (value) => {
    return (typeof value === "number" && value > 0) || (typeof value === "string" && validators.isISO8601Duration(value));
  },

  isTOTP: (value) => {
    // Check if it's a string of 6 digits
    if (typeof value === "string") {
      return /^\d{6}$/.test(value);
    }
    // Check if it's a number between 000000 and 999999
    if (typeof value === "number") {
      return value >= 0 && value <= 999999 && Number.isInteger(value);
    }
    return false;
  },

  isBoolean: (value) => typeof value === "boolean",
  isValidDate: (value) => value instanceof Date && !isNaN(value),
  isObject: (value) => typeof value === "object" && value !== null && !Array.isArray(value),
  isArray: (value) => Array.isArray(value),
  // Add more validators as needed
};

module.exports = validators;
