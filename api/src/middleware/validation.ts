import { body, check, param, query, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { StrKey } from '@stellar/stellar-sdk';
import { ValidationError } from '../utils/errors';

const VALID_OPERATIONS = ['deposit', 'borrow', 'repay', 'withdraw'];
const VALID_IMPORT_FORMATS = ['csv', 'json'];
const MAX_XDR_LENGTH = 20000;
const MAX_ASSET_ID_LENGTH = 128;

export const validateRequest = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors
      .array()
      .map((err) => err.msg)
      .join(', ');
    throw new ValidationError(errorMessages);
  }
  next();
};

export const amountValidation = [
  check('amount')
    .notEmpty()
    .withMessage('Amount is required')
    .custom((value) => {
      const errMsg = 'Amount must be a valid positive integer';

      try {
        const str = String(value).trim();
        if (!/^\+?\d+$/.test(str)) {
          throw new Error(errMsg);
        }

        const amount = BigInt(str);
        if (amount <= 0n) {
          throw new Error(errMsg);
        }

        const maxI128 = (1n << 127n) - 1n;
        if (amount > maxI128) {
          throw new Error(errMsg);
        }

        return true;
      } catch {
        throw new Error(errMsg);
      }
    }),
];

const createLendingValidation = () => [
  param('operation')
    .isIn(VALID_OPERATIONS)
    .withMessage(`Operation must be one of: ${VALID_OPERATIONS.join(', ')}`),
  check('userAddress')
    .notEmpty()
    .withMessage('User address is required')
    .custom((value) => {
      if (!StrKey.isValidEd25519PublicKey(value)) {
        throw new Error('Invalid Stellar address');
      }
      return true;
    }),
  ...amountValidation,
  check('assetAddress')
    .optional()
    .isString()
    .trim()
    .notEmpty()
    .isLength({ max: MAX_ASSET_ID_LENGTH })
    .withMessage('Asset address must be a non-empty string <= 128 chars'),
  validateRequest,
];

export const prepareValidation = createLendingValidation();

export const submitValidation = [
  body('signedXdr')
    .isString()
    .notEmpty()
    .isLength({ max: MAX_XDR_LENGTH })
    .withMessage('signedXdr is required and must be <= 20000 characters'),
  body('operation')
    .optional()
    .isIn(VALID_OPERATIONS)
    .withMessage(`Operation must be one of: ${VALID_OPERATIONS.join(', ')}`),
  body('userAddress')
    .optional()
    .custom((value) => {
      if (value && !StrKey.isValidEd25519PublicKey(value)) {
        throw new Error('Invalid Stellar address');
      }
      return true;
    }),
  body('amount')
    .optional()
    .custom((value) => {
      if (!value) return true;

      const errMsg = 'Amount must be a valid positive integer';
      try {
        const str = String(value).trim();
        if (!/^\+?\d+$/.test(str)) {
          throw new Error(errMsg);
        }

        const amount = BigInt(str);
        if (amount <= 0n) {
          throw new Error(errMsg);
        }

        const maxI128 = (1n << 127n) - 1n;
        if (amount > maxI128) {
          throw new Error(errMsg);
        }

        return true;
      } catch {
        throw new Error(errMsg);
      }
    }),
  body('assetAddress')
    .optional()
    .isString()
    .trim()
    .notEmpty()
    .isLength({ max: MAX_ASSET_ID_LENGTH })
    .withMessage('Asset address must be a non-empty string <= 128 chars'),
  validateRequest,
];

export const importRequestValidation = [
  body('merchantId').isString().notEmpty().withMessage('merchantId is required'),
  body('format')
    .isIn(VALID_IMPORT_FORMATS)
    .withMessage(`format must be one of: ${VALID_IMPORT_FORMATS.join(', ')}`),
  body('data')
    .custom((value) => typeof value === 'string' || Array.isArray(value))
    .withMessage('data must be a CSV string or JSON array'),
  body('columnMapping')
    .optional()
    .custom((value) => {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error('columnMapping must be an object');
      }
      return true;
    }),
  body('options')
    .optional()
    .custom((value) => {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error('options must be an object');
      }
      return true;
    }),
  validateRequest,
];

export const merchantParamValidation = [
  param('merchantId').isString().notEmpty().withMessage('merchantId is required'),
  validateRequest,
];

export const paginationValidation = [
  query('limit')
    .optional()
    .isInt({ min: 1, max: parseInt(process.env.PAGINATION_MAX_LIMIT || '100', 10) })
    .withMessage('limit must be a positive integer and at most the configured max'),
  query('cursor')
    .optional()
    .isString()
    .isLength({ max: 256 })
    .notEmpty()
    .withMessage('cursor must be a non-empty string and <= 256 chars'),
  validateRequest,
];

export const depositValidation = createLendingValidation();
export const borrowValidation = createLendingValidation();
export const repayValidation = createLendingValidation();
export const withdrawValidation = createLendingValidation();

export const relayDelegatedValidation = [
  body('delegatorAddress')
    .notEmpty()
    .withMessage('delegatorAddress is required')
    .custom((value) => {
      if (!StrKey.isValidEd25519PublicKey(value)) {
        throw new Error('Invalid Stellar address');
      }
      return true;
    }),
  body('nonce').isString().notEmpty().withMessage('nonce is required'),
  body('deadline').isString().notEmpty().withMessage('deadline is required'),
  body('callsXdr')
    .isString()
    .notEmpty()
    .isLength({ max: MAX_XDR_LENGTH })
    .withMessage('callsXdr is required and must be <= 20000 characters'),
  validateRequest,
];

// Leverage validation middleware
const validateStellarAddress = (value: string, fieldName: string) => {
  if (!StrKey.isValidEd25519PublicKey(value)) {
    throw new Error(`Invalid Stellar ${fieldName}`);
  }
  return true;
};

const validatePositiveIntegerString = (value: string, fieldName: string) => {
  const errMsg = `${fieldName} must be a valid positive integer`;
  try {
    const str = String(value).trim();
    if (!/^\+?\d+$/.test(str)) {
      throw new Error(errMsg);
    }
    const amount = BigInt(str);
    if (amount <= 0n) {
      throw new Error(errMsg);
    }
    const maxI128 = (1n << 127n) - 1n;
    if (amount > maxI128) {
      throw new Error(errMsg);
    }
    return true;
  } catch {
    throw new Error(errMsg);
  }
};

export const leveragePrepareValidation = [
  body('userAddress')
    .notEmpty()
    .withMessage('userAddress is required')
    .custom((value) => validateStellarAddress(value, 'userAddress')),
  body('collateralAsset')
    .notEmpty()
    .withMessage('collateralAsset is required')
    .custom((value) => validateStellarAddress(value, 'collateralAsset')),
  body('borrowAsset')
    .notEmpty()
    .withMessage('borrowAsset is required')
    .custom((value) => validateStellarAddress(value, 'borrowAsset')),
  body('collateralAmount')
    .notEmpty()
    .withMessage('collateralAmount is required')
    .custom((value) => validatePositiveIntegerString(value, 'collateralAmount')),
  body('targetLeverage')
    .notEmpty()
    .withMessage('targetLeverage is required')
    .isFloat({ min: 1, max: 10 })
    .withMessage('targetLeverage must be a number between 1 and 10'),
  body('minHealthFactor')
    .optional()
    .isFloat({ min: 1.0, max: 5.0 })
    .withMessage('minHealthFactor must be a number between 1.0 and 5.0'),
  body('slippageTolerance')
    .optional()
    .isFloat({ min: 0, max: 0.5 })
    .withMessage('slippageTolerance must be a number between 0 and 0.5'),
  body('loopCount')
    .optional()
    .isInt({ min: 1, max: 5 })
    .withMessage('loopCount must be an integer between 1 and 5'),
  validateRequest,
];

export const leverageSimulateValidation = [
  body('userAddress')
    .notEmpty()
    .withMessage('userAddress is required')
    .custom((value) => validateStellarAddress(value, 'userAddress')),
  body('collateralAsset')
    .notEmpty()
    .withMessage('collateralAsset is required')
    .custom((value) => validateStellarAddress(value, 'collateralAsset')),
  body('borrowAsset')
    .notEmpty()
    .withMessage('borrowAsset is required')
    .custom((value) => validateStellarAddress(value, 'borrowAsset')),
  body('collateralAmount')
    .notEmpty()
    .withMessage('collateralAmount is required')
    .custom((value) => validatePositiveIntegerString(value, 'collateralAmount')),
  body('targetLeverage')
    .notEmpty()
    .withMessage('targetLeverage is required')
    .isFloat({ min: 1, max: 10 })
    .withMessage('targetLeverage must be a number between 1 and 10'),
  body('minHealthFactor')
    .optional()
    .isFloat({ min: 1.0, max: 5.0 })
    .withMessage('minHealthFactor must be a number between 1.0 and 5.0'),
  body('slippageTolerance')
    .optional()
    .isFloat({ min: 0, max: 0.5 })
    .withMessage('slippageTolerance must be a number between 0 and 0.5'),
  body('loopCount')
    .optional()
    .isInt({ min: 1, max: 5 })
    .withMessage('loopCount must be an integer between 1 and 5'),
  validateRequest,
];

export const leverageExecuteValidation = [
  body('signedXdr')
    .isString()
    .notEmpty()
    .isLength({ max: MAX_XDR_LENGTH })
    .withMessage('signedXdr is required and must be <= 20000 characters'),
  body('userAddress')
    .notEmpty()
    .withMessage('userAddress is required')
    .custom((value) => validateStellarAddress(value, 'userAddress')),
  body('minHealthFactor')
    .notEmpty()
    .withMessage('minHealthFactor is required')
    .isFloat({ min: 1.0, max: 5.0 })
    .withMessage('minHealthFactor must be a number between 1.0 and 5.0'),
  body('operation')
    .optional()
    .isIn(['leverage_loop'])
    .withMessage('operation must be leverage_loop'),
  validateRequest,
];

export const leverageHealthFactorValidation = [
  query('userAddress')
    .notEmpty()
    .withMessage('userAddress is required')
    .custom((value) => validateStellarAddress(value, 'userAddress')),
  query('collateralAsset')
    .optional()
    .custom((value) => {
      if (value && !StrKey.isValidEd25519PublicKey(value)) {
        throw new Error('Invalid Stellar collateralAsset');
      }
      return true;
    }),
  query('borrowAsset')
    .optional()
    .custom((value) => {
      if (value && !StrKey.isValidEd25519PublicKey(value)) {
        throw new Error('Invalid Stellar borrowAsset');
      }
      return true;
    }),
  query('simulateLeverage')
    .optional()
    .isFloat({ min: 1, max: 10 })
    .withMessage('simulateLeverage must be a number between 1 and 10'),
  query('simulateAmount')
    .optional()
    .custom((value) => {
      if (!value) return true;
      return validatePositiveIntegerString(value, 'simulateAmount');
    }),
  validateRequest,
];
