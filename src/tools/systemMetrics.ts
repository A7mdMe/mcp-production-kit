import os from 'os';
import { z } from 'zod';

export const SystemMetricsInputSchema = z.object({
  includeMemoryDetails: z.boolean().default(true).describe('Include detailed heap and system memory breakdown'),
  includeNetworkInterfaces: z.boolean().default(false).describe('Include active network interface configurations')
});

export type SystemMetricsInput = z.infer<typeof SystemMetricsInputSchema>;

export async function executeSystemMetrics(input: SystemMetricsInput) {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memoryUsagePercent = ((usedMem / totalMem) * 100).toFixed(2);

  const processMem = process.memoryUsage();

  const cpus = os.cpus();
  const uptimeSeconds = os.uptime();
  const processUptimeSeconds = process.uptime();

  const metrics: Record<string, unknown> = {
    os: {
      platform: os.platform(),
      release: os.release(),
      arch: os.arch(),
      hostname: os.hostname(),
      systemUptimeHours: (uptimeSeconds / 3600).toFixed(2),
      processUptimeMinutes: (processUptimeSeconds / 60).toFixed(2)
    },
    cpu: {
      model: cpus[0]?.model || 'Unknown',
      cores: cpus.length,
      loadAverage: os.loadavg()
    },
    memory: {
      totalMb: Math.round(totalMem / (1024 * 1024)),
      usedMb: Math.round(usedMem / (1024 * 1024)),
      freeMb: Math.round(freeMem / (1024 * 1024)),
      usagePercentage: `${memoryUsagePercent}%`
    }
  };

  if (input.includeMemoryDetails) {
    metrics.processMemory = {
      rssMb: Math.round(processMem.rss / (1024 * 1024)),
      heapTotalMb: Math.round(processMem.heapTotal / (1024 * 1024)),
      heapUsedMb: Math.round(processMem.heapUsed / (1024 * 1024)),
      externalMb: Math.round(processMem.external / (1024 * 1024))
    };
  }

  if (input.includeNetworkInterfaces) {
    metrics.network = os.networkInterfaces();
  }

  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(metrics, null, 2)
      }
    ]
  };
}
