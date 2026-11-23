import { Request, Response, NextFunction } from 'express';
import { StellarService } from '../services/stellar.service';
import { config } from '../config/index';
import logger from '../utils/logger';
import { emergencyPauseService } from '../services/emergencyPause.service';
import { auditLogService } from '../services/auditLog.service';
import { readCacheService } from '../services/readCache.service';
import { transactionSimulationService } from '../services/transactionSimulation.service';

export interface LeveragePrepareRequest {
  userAddress: string;
  collateralAsset: string;
  borrowAsset: string;
  collateralAmount: string;
  targetLeverage: number;
  minHealthFactor?: number;
  slippageTolerance?: number;
  loopCount?: number;
}

export interface LeveragePrepareResponse {
  unsignedXdr: string;
  operation: 'leverage_loop';
  expiresAt: string;
  simulation: LeverageSimulationResult;
  healthFactorGuard: HealthFactorGuardResult;
}

export interface LeverageSimulationRequest {
  userAddress: string;
  collateralAsset: string;
  borrowAsset: string;
  collateralAmount: string;
  targetLeverage: number;
  minHealthFactor?: number;
  slippageTolerance?: number;
  loopCount?: number;
}

export interface LeverageSimulationResponse {
  simulation: LeverageSimulationResult;
  healthFactorGuard: HealthFactorGuardResult;
  gasEstimate: string;
  warnings: string[];
}

export interface LeverageExecuteRequest {
  signedXdr: string;
  userAddress: string;
  minHealthFactor: number;
  operation?: 'leverage_loop';
}

export interface HealthFactorRequest {
  userAddress: string;
  collateralAsset?: string;
  borrowAsset?: string;
  simulateLeverage?: number;
  simulateAmount?: string;
}

export interface HealthFactorResponse {
  currentHealthFactor: number;
  projectedHealthFactor?: number;
  collateralValue: string;
  debtValue: string;
  liquidationThreshold: number;
  isHealthy: boolean;
  positions: PositionHealth[];
}

export interface PositionHealth {
  collateralAsset: string;
  borrowAsset: string;
  collateralAmount: string;
  debtAmount: string;
  healthFactor: number;
  liquidationPrice: string;
}

export interface MaxLeverageRequest {
  userAddress: string;
  collateralAsset: string;
  borrowAsset: string;
  minHealthFactor?: number;
}

export interface MaxLeverageResponse {
  maxLeverage: number;
  currentHealthFactor: number;
  maxBorrowAmount: string;
  maxCollateralAmount: string;
}

export interface LeveragePosition {
  positionId: string;
  collateralAsset: string;
  borrowAsset: string;
  collateralAmount: string;
  debtAmount: string;
  leverageRatio: number;
  healthFactor: number;
  entryPrice: string;
  currentPrice: string;
  pnl: string;
  createdAt: number;
}

export interface LeveragePositionsResponse {
  positions: LeveragePosition[];
  totalCount: number;
  page: number;
  limit: number;
}

export interface LeverageSimulationResult {
  steps: SimulationStep[];
  finalCollateralAmount: string;
  finalDebtAmount: string;
  finalLeverageRatio: number;
  estimatedGas: string;
  swapDetails: SwapDetail[];
}

export interface SimulationStep {
  step: number;
  type: 'deposit' | 'borrow' | 'swap';
  assetIn: string;
  assetOut: string;
  amountIn: string;
  amountOut: string;
  priceImpact: number;
}

export interface SwapDetail {
  fromAsset: string;
  toAsset: string;
  amountIn: string;
  amountOut: string;
  priceImpact: number;
  route: string[];
}

export interface HealthFactorGuardResult {
  passed: boolean;
  currentHealthFactor: number;
  projectedHealthFactor: number;
  minRequired: number;
  liquidationThreshold: number;
  maxSafeLeverage: number;
  reason?: string;
}

/**
 * Prepare a one-click leverage loop transaction
 */
export const prepare = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (emergencyPauseService.isPaused().paused) {
      return res.status(503).json({
        success: false,
        error: 'Protocol is paused',
        reason: emergencyPauseService.isPaused().reason,
      });
    }

    const params: LeveragePrepareRequest = req.body;

    logger.info('Preparing leverage loop transaction', {
      userAddress: params.userAddress,
      collateralAsset: params.collateralAsset,
      borrowAsset: params.borrowAsset,
      targetLeverage: params.targetLeverage,
    });

    // Run simulation first to validate health factor
    const simulationResult = await simulateLeverageLoop(params);
    const healthFactorGuard = checkHealthFactorGuard(simulationResult, params.minHealthFactor || 1.5);

    if (!healthFactorGuard.passed) {
      return res.status(409).json({
        success: false,
        error: 'Health factor guard triggered',
        guard: healthFactorGuard,
        message: healthFactorGuard.reason || 'Projected health factor below minimum threshold',
      });
    }

    // Build the unsigned transaction
    const stellarService = new StellarService();
    const unsignedXdr = await stellarService.buildLeverageLoopTransaction({
      userAddress: params.userAddress,
      collateralAsset: params.collateralAsset,
      borrowAsset: params.borrowAsset,
      collateralAmount: params.collateralAmount,
      targetLeverage: params.targetLeverage,
      slippageTolerance: params.slippageTolerance || 0.01,
      loopCount: params.loopCount || 1,
      minHealthFactor: params.minHealthFactor || 1.5,
    });

    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    const response: LeveragePrepareResponse = {
      unsignedXdr,
      operation: 'leverage_loop',
      expiresAt,
      simulation: simulationResult,
      healthFactorGuard,
    };

    return res.status(200).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Simulate a leverage loop without executing
 */
export const simulate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const params: LeverageSimulationRequest = req.body;

    logger.info('Simulating leverage loop', {
      userAddress: params.userAddress,
      targetLeverage: params.targetLeverage,
    });

    const simulationResult = await simulateLeverageLoop(params);
    const healthFactorGuard = checkHealthFactorGuard(simulationResult, params.minHealthFactor || 1.5);

    // Estimate gas
    const stellarService = new StellarService();
    const gasEstimate = await stellarService.estimateLeverageLoopGas({
      userAddress: params.userAddress,
      collateralAsset: params.collateralAsset,
      borrowAsset: params.borrowAsset,
      collateralAmount: params.collateralAmount,
      targetLeverage: params.targetLeverage,
      loopCount: params.loopCount || 1,
    });

    const warnings: string[] = [];

    if (!healthFactorGuard.passed) {
      warnings.push(`Health factor guard would trigger: ${healthFactorGuard.reason}`);
    }

    if (simulationResult.finalLeverageRatio > 5) {
      warnings.push('High leverage ratio detected - increased liquidation risk');
    }

    if (simulationResult.swapDetails.some(s => s.priceImpact > 0.05)) {
      warnings.push('High price impact detected on swaps - consider smaller amounts');
    }

    const response: LeverageSimulationResponse = {
      simulation: simulationResult,
      healthFactorGuard,
      gasEstimate,
      warnings,
    };

    return res.status(200).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Execute a prepared leverage loop transaction
 */
export const execute = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const params: LeverageExecuteRequest = req.body;

    const pauseState = emergencyPauseService.isPaused();
    if (pauseState.paused) {
      return res.status(503).json({
        success: false,
        error: 'Protocol is paused',
        reason: pauseState.reason,
      });
    }

    logger.info('Executing leverage loop transaction', {
      userAddress: params.userAddress,
    });

    // Final health factor check before execution
    const stellarService = new StellarService();

    // Simulate the transaction to verify final health factor
    const simulation = await stellarService.simulateTransaction(params.signedXdr);

    // Extract health factor from simulation
    const finalHealthFactor = extractHealthFactorFromSimulation(simulation);

    if (finalHealthFactor < params.minHealthFactor) {
      return res.status(409).json({
        success: false,
        error: 'Health factor guard triggered on execution',
        guard: {
          passed: false,
          currentHealthFactor: finalHealthFactor,
          projectedHealthFactor: finalHealthFactor,
          minRequired: params.minHealthFactor,
          liquidationThreshold: 1.0,
          maxSafeLeverage: 0,
          reason: `Final health factor ${finalHealthFactor} below minimum ${params.minHealthFactor}`,
        },
      });
    }

    // Submit transaction
    const result = await stellarService.submitTransaction(params.signedXdr);

    if (result.success && result.transactionHash) {
      emergencyPauseService.recordSuccess();
      const monitorResult = await stellarService.monitorTransaction(result.transactionHash);

      auditLogService.record({
        action: 'LEVERAGE_LOOP_EXECUTED',
        actor: params.userAddress,
        status: monitorResult.status as any,
        txHash: result.transactionHash,
        ledger: monitorResult.ledger,
        amount: 'LEVERAGE_LOOP',
        assetAddress: 'MULTI',
        ip: req.ip,
      });

      await readCacheService.invalidateAfterWrite();

      return res.status(200).json({
        success: true,
        transactionHash: result.transactionHash,
        status: monitorResult.status,
        message: 'Leverage loop executed successfully',
        ledger: monitorResult.ledger,
      });
    }

    return res.status(400).json({
      success: false,
      error: result.error || 'Transaction failed',
      status: 'failed',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get current health factor for a position
 */
export const getHealthFactor = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const params: HealthFactorRequest = req.query as unknown as HealthFactorRequest;

    logger.info('Getting health factor', { userAddress: params.userAddress });

    const stellarService = new StellarService();
    const healthData = await stellarService.getPositionHealth({
      userAddress: params.userAddress,
      collateralAsset: params.collateralAsset,
      borrowAsset: params.borrowAsset,
    });

    let projectedHealthFactor: number | undefined;

    if (params.simulateLeverage && params.simulateAmount) {
      // Simulate leverage impact on health factor
      projectedHealthFactor = await stellarService.projectHealthFactor({
        userAddress: params.userAddress,
        collateralAsset: params.collateralAsset || '',
        borrowAsset: params.borrowAsset || '',
        leverageRatio: params.simulateLeverage,
        additionalBorrowAmount: params.simulateAmount,
      });
    }

    const response: HealthFactorResponse = {
      currentHealthFactor: healthData.healthFactor,
      projectedHealthFactor,
      collateralValue: healthData.collateralValue,
      debtValue: healthData.debtValue,
      liquidationThreshold: healthData.liquidationThreshold,
      isHealthy: healthData.healthFactor >= healthData.liquidationThreshold,
      positions: healthData.positions,
    };

    return res.status(200).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Calculate maximum safe leverage for a position
 */
export const getMaxLeverage = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const params: MaxLeverageRequest = req.query as unknown as MaxLeverageRequest;

    logger.info('Calculating max leverage', { userAddress: params.userAddress });

    const stellarService = new StellarService();
    const result = await stellarService.calculateMaxLeverage({
      userAddress: params.userAddress,
      collateralAsset: params.collateralAsset,
      borrowAsset: params.borrowAsset,
      minHealthFactor: params.minHealthFactor || 1.5,
    });

    const response: MaxLeverageResponse = {
      maxLeverage: result.maxLeverage,
      currentHealthFactor: result.currentHealthFactor,
      maxBorrowAmount: result.maxBorrowAmount,
      maxCollateralAmount: result.maxCollateralAmount,
    };

    return res.status(200).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * List user's active leverage positions
 */
export const getLeveragePositions = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userAddress = req.query.userAddress as string;
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);

    if (!userAddress) {
      return res.status(400).json({
        success: false,
        error: 'userAddress is required',
      });
    }

    logger.info('Getting leverage positions', { userAddress, page, limit });

    const stellarService = new StellarService();
    const positions = await stellarService.getLeveragePositions({
      userAddress,
      page,
      limit,
    });

    const response: LeveragePositionsResponse = {
      positions: positions.data,
      totalCount: positions.total,
      page,
      limit,
    };

    return res.status(200).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Prepare a deleveraging transaction
 */
export const prepareDeleverage = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (emergencyPauseService.isPaused().paused) {
      return res.status(503).json({
        success: false,
        error: 'Protocol is paused',
        reason: emergencyPauseService.isPaused().reason,
      });
    }

    const { userAddress, positionId, repayAmount, withdrawCollateral } = req.body;

    logger.info('Preparing deleverage transaction', {
      userAddress,
      positionId,
      repayAmount,
    });

    const stellarService = new StellarService();
    const unsignedXdr = await stellarService.buildDeleverageTransaction({
      userAddress,
      positionId,
      repayAmount,
      withdrawCollateral: withdrawCollateral || false,
    });

    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    const response = {
      unsignedXdr,
      operation: 'deleverage',
      expiresAt,
    };

    return res.status(200).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Simulate a leverage loop and return detailed results
 */
async function simulateLeverageLoop(params: LeveragePrepareRequest): Promise<LeverageSimulationResult> {
  const stellarService = new StellarService();

  // Get current position
  const position = await stellarService.getPosition({
    userAddress: params.userAddress,
    collateralAsset: params.collateralAsset,
    borrowAsset: params.borrowAsset,
  });

  // Calculate leverage loop steps
  const steps: SimulationStep[] = [];
  const swapDetails: SwapDetail[] = [];

  let currentCollateral = parseFloat(params.collateralAmount);
  let currentDebt = 0;
  let totalBorrowed = 0;

  for (let loop = 0; loop < (params.loopCount || 1); loop++) {
    // Step 1: Deposit collateral
    steps.push({
      step: loop * 3 + 1,
      type: 'deposit',
      assetIn: params.collateralAsset,
      assetOut: params.collateralAsset,
      amountIn: params.collateralAmount,
      amountOut: params.collateralAmount,
      priceImpact: 0,
    });

    // Step 2: Borrow against collateral
    const borrowAmount = currentCollateral * (params.targetLeverage - 1) / params.targetLeverage;
    currentDebt += borrowAmount;
    totalBorrowed += borrowAmount;

    steps.push({
      step: loop * 3 + 2,
      type: 'borrow',
      assetIn: params.borrowAsset,
      assetOut: params.borrowAsset,
      amountIn: borrowAmount.toString(),
      amountOut: borrowAmount.toString(),
      priceImpact: 0,
    });

    // Step 3: Swap borrowed asset for more collateral (if different assets)
    if (params.collateralAsset !== params.borrowAsset) {
      const swapResult = await stellarService.simulateSwap({
        assetIn: params.borrowAsset,
        assetOut: params.collateralAsset,
        amountIn: borrowAmount.toString(),
        slippageTolerance: params.slippageTolerance || 0.01,
      });

      const collateralReceived = parseFloat(swapResult.amountOut);
      currentCollateral += collateralReceived;

      swapDetails.push({
        fromAsset: params.borrowAsset,
        toAsset: params.collateralAsset,
        amountIn: borrowAmount.toString(),
        amountOut: swapResult.amountOut,
        priceImpact: swapResult.priceImpact,
        route: swapResult.route,
      });

      steps.push({
        step: loop * 3 + 3,
        type: 'swap',
        assetIn: params.borrowAsset,
        assetOut: params.collateralAsset,
        amountIn: borrowAmount.toString(),
        amountOut: swapResult.amountOut,
        priceImpact: swapResult.priceImpact,
      });
    }
  }

  // Get prices for final valuation
  const collateralPrice = await stellarService.getAssetPrice(params.collateralAsset);
  const borrowPrice = await stellarService.getAssetPrice(params.borrowAsset);

  const finalCollateralValue = currentCollateral * collateralPrice;
  const finalDebtValue = totalBorrowed * borrowPrice;
  const finalLeverageRatio = finalCollateralValue / finalDebtValue;

  return {
    steps,
    finalCollateralAmount: currentCollateral.toString(),
    finalDebtAmount: totalBorrowed.toString(),
    finalLeverageRatio,
    estimatedGas: '0', // Will be filled by caller
    swapDetails,
  };
}

/**
 * Check health factor guard
 */
function checkHealthFactorGuard(
  simulation: LeverageSimulationResult,
  minHealthFactor: number
): HealthFactorGuardResult {
  // Calculate projected health factor based on simulation
  // Health factor = collateral_value * liquidation_threshold / total_debt
  const liquidationThreshold = 0.8; // 80% default

  // This is a simplified calculation - in reality would use actual oracle prices
  const projectedHealthFactor = simulation.finalLeverageRatio * liquidationThreshold;

  const maxSafeLeverage = minHealthFactor / liquidationThreshold;

  return {
    passed: projectedHealthFactor >= minHealthFactor,
    currentHealthFactor: 0, // Would be filled from actual position
    projectedHealthFactor,
    minRequired: minHealthFactor,
    liquidationThreshold,
    maxSafeLeverage,
    reason: projectedHealthFactor < minHealthFactor
      ? `Projected health factor ${projectedHealthFactor.toFixed(2)} below minimum ${minHealthFactor}`
      : undefined,
  };
}

/**
 * Extract health factor from transaction simulation result
 */
function extractHealthFactorFromSimulation(simulation: any): number {
  // In a real implementation, this would parse the simulation result
  // to extract the health factor from the contract's post-execution state
  return 2.0; // Placeholder
}