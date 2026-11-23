import { Router } from 'express';
import * as leverageController from '../controllers/leverage.controller';
import {
  leveragePrepareValidation,
  leverageExecuteValidation,
  leverageSimulateValidation,
  leverageHealthFactorValidation,
} from '../middleware/validation';

const router: Router = Router();

/**
 * @openapi
 * /leverage/prepare:
 *   post:
 *     summary: Prepare a one-click leverage loop transaction
 *     description: Builds an unsigned Soroban transaction XDR for a leverage loop operation (deposit + borrow in a single atomic transaction). Includes health factor simulation and validation.
 *     tags:
 *       - Leverage
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userAddress
 *               - collateralAsset
 *               - borrowAsset
 *               - collateralAmount
 *               - targetLeverage
 *             properties:
 *               userAddress:
 *                 type: string
 *                 description: Stellar public key (Ed25519)
 *               collateralAsset:
 *                 type: string
 *                 description: Collateral asset contract address
 *               borrowAsset:
 *                 type: string
 *                 description: Borrow asset contract address
 *               collateralAmount:
 *                 type: string
 *                 description: Collateral amount as positive integer string (stroops)
 *               targetLeverage:
 *                 type: number
 *                 format: float
 *                 minimum: 1
 *                 maximum: 10
 *                 description: Target leverage ratio (e.g., 2.0 for 2x leverage)
 *               minHealthFactor:
 *                 type: number
 *                 format: float
 *                 minimum: 1.0
 *                 maximum: 5.0
 *                 default: 1.5
 *                 description: Minimum acceptable health factor after leverage (default: 1.5)
 *               slippageTolerance:
 *                 type: number
 *                 format: float
 *                 minimum: 0
 *                 maximum: 0.5
 *                 default: 0.01
 *                 description: Maximum slippage tolerance for swaps (default: 1%)
 *               loopCount:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 5
 *                 default: 1
 *                 description: Number of leverage loops to execute (default: 1)
 *     responses:
 *       200:
 *         description: Unsigned transaction XDR with health factor simulation
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LeveragePrepareResponse'
 *       400:
 *         description: Validation error or health factor below minimum
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       409:
 *         description: Health factor guard triggered - position would be undercollateralized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthFactorGuardResponse'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post('/prepare', leveragePrepareValidation, leverageController.prepare);

/**
 * @openapi
 * /leverage/simulate:
 *   post:
 *     summary: Simulate a leverage loop without executing
 *     description: Runs a full simulation of the leverage loop including health factor calculation, swap impact, and gas estimation. Does not execute any transactions.
 *     tags:
 *       - Leverage
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userAddress
 *               - collateralAsset
 *               - borrowAsset
 *               - collateralAmount
 *               - targetLeverage
 *             properties:
 *               userAddress:
 *                 type: string
 *                 description: Stellar public key (Ed25519)
 *               collateralAsset:
 *                 type: string
 *                 description: Collateral asset contract address
 *               borrowAsset:
 *                 type: string
 *                 description: Borrow asset contract address
 *               collateralAmount:
 *                 type: string
 *                 description: Collateral amount as positive integer string (stroops)
 *               targetLeverage:
 *                 type: number
 *                 format: float
 *                 minimum: 1
 *                 maximum: 10
 *                 description: Target leverage ratio
 *               minHealthFactor:
 *                 type: number
 *                 format: float
 *                 minimum: 1.0
 *                 maximum: 5.0
 *                 default: 1.5
 *               slippageTolerance:
 *                 type: number
 *                 format: float
 *                 minimum: 0
 *                 maximum: 0.5
 *                 default: 0.01
 *               loopCount:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 5
 *                 default: 1
 *     responses:
 *       200:
 *         description: Simulation results with health factor analysis
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LeverageSimulationResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post('/simulate', leverageSimulateValidation, leverageController.simulate);

/**
 * @openapi
 * /leverage/execute:
 *   post:
 *     summary: Execute a prepared leverage loop transaction
 *     description: Submits a client-signed leverage loop transaction XDR to the Stellar network. Includes final health factor verification before execution.
 *     tags:
 *       - Leverage
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - signedXdr
 *               - userAddress
 *               - minHealthFactor
 *             properties:
 *               signedXdr:
 *                 type: string
 *                 description: Signed transaction XDR from prepare endpoint
 *               userAddress:
 *                 type: string
 *                 description: Stellar public key (Ed25519)
 *               minHealthFactor:
 *                 type: number
 *                 format: float
 *                 minimum: 1.0
 *                 maximum: 5.0
 *                 description: Minimum health factor to allow execution (guard)
 *               operation:
 *                 type: string
 *                 enum: [leverage_loop]
 *                 description: Operation type for audit logging
 *     responses:
 *       200:
 *         description: Transaction submitted successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TransactionResponse'
 *       400:
 *         description: Invalid transaction or health factor check failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       409:
 *         description: Health factor guard triggered - final check failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthFactorGuardResponse'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post('/execute', leverageExecuteValidation, leverageController.execute);

/**
 * @openapi
 * /leverage/health-factor:
 *   get:
 *     summary: Get current health factor for a position
 *     description: Calculates and returns the current health factor for a user's position, including projected health factor after a hypothetical leverage operation.
 *     tags:
 *       - Leverage
 *     parameters:
 *       - in: query
 *         name: userAddress
 *         required: true
 *         schema:
 *           type: string
 *           description: Stellar public key (Ed25519)
 *       - in: query
 *         name: collateralAsset
 *         required: false
 *         schema:
 *           type: string
 *           description: Collateral asset contract address (optional, checks all if not specified)
 *       - in: query
 *         name: borrowAsset
 *         required: false
 *         schema:
 *           type: string
 *           description: Borrow asset contract address (optional, checks all if not specified)
 *       - in: query
 *         name: simulateLeverage
 *         required: false
 *         schema:
 *           type: number
 *           format: float
 *           minimum: 1
 *           maximum: 10
 *           description: Simulate leverage ratio to project health factor
 *       - in: query
 *         name: simulateAmount
 *         required: false
 *         schema:
 *           type: string
 *           description: Amount to simulate borrowing
 *     responses:
 *       200:
 *         description: Current and projected health factors
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthFactorResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get('/health-factor', leverageHealthFactorValidation, leverageController.getHealthFactor);

/**
 * @openapi
 * /leverage/max-leverage:
 *   get:
 *     summary: Calculate maximum safe leverage for a position
 *     description: Determines the maximum leverage ratio achievable while maintaining a minimum health factor.
 *     tags:
 *       - Leverage
 *     parameters:
 *       - in: query
 *         name: userAddress
 *         required: true
 *         schema:
 *           type: string
 *           description: Stellar public key (Ed25519)
 *       - in: query
 *         name: collateralAsset
 *         required: true
 *         schema:
 *           type: string
 *           description: Collateral asset contract address
 *       - in: query
 *         name: borrowAsset
 *         required: true
 *         schema:
 *           type: string
 *           description: Borrow asset contract address
 *       - in: query
 *         name: minHealthFactor
 *         required: false
 *         schema:
 *           type: number
 *           format: float
 *           minimum: 1.0
 *           maximum: 5.0
 *           default: 1.5
 *           description: Minimum required health factor
 *     responses:
 *       200:
 *         description: Maximum safe leverage ratio
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MaxLeverageResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get('/max-leverage', leverageController.getMaxLeverage);

/**
 * @openapi
 * /leverage/positions:
 *   get:
 *     summary: List user's active leverage positions
 *     description: Returns all active leverage loop positions for a user, including current health factors and leverage ratios.
 *     tags:
 *       - Leverage
 *     parameters:
 *       - in: query
 *         name: userAddress
 *         required: true
 *         schema:
 *           type: string
 *           description: Stellar public key (Ed25519)
 *       - in: query
 *         name: page
 *         required: false
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *       - in: query
 *         name: limit
 *         required: false
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *     responses:
 *       200:
 *         description: List of leverage positions
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LeveragePositionsResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get('/positions', leverageController.getLeveragePositions);

/**
 * @openapi
 * /leverage/deleverage:
 *   post:
 *     summary: Prepare a deleveraging transaction
 *     description: Builds an unsigned transaction to reduce leverage by repaying debt and withdrawing collateral.
 *     tags:
 *       - Leverage
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userAddress
 *               - positionId
 *               - repayAmount
 *             properties:
 *               userAddress:
 *                 type: string
 *                 description: Stellar public key (Ed25519)
 *               positionId:
 *                 type: string
 *                 description: Leverage position ID
 *               repayAmount:
 *                 type: string
 *                 description: Amount to repay as positive integer string (stroops)
 *               withdrawCollateral:
 *                 type: boolean
 *                 default: false
 *                 description: Whether to withdraw freed collateral
 *     responses:
 *       200:
 *         description: Unsigned deleveraging transaction XDR
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LeveragePrepareResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post('/deleverage', leverageController.prepareDeleverage);

export default router;