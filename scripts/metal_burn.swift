// Metal GPU burn with Metal's own GPU time, to check denet's `gpu_time_ns`:
//   swiftc -O scripts/metal_burn.swift -o metal_burn
//   denet --gpu -j -o out.json run ./metal_burn SECS THREADS BUFFER_MS DUTY
// e.g. ./metal_burn 8 1048576 20 1.0 = 8 s of 1M-thread, 20 ms command buffers, no idle gaps.
import Metal
import Foundation
let dev = MTLCreateSystemDefaultDevice()!
let src = """
kernel void burn(device float *o [[buffer(0)]], constant int &iters [[buffer(1)]], uint i [[thread_position_in_grid]]) {
  float x = i; for (int k = 0; k < iters; k++) x = x * 1.0000001 + 0.5; o[i] = x; }
"""
let lib = try! dev.makeLibrary(source: src, options: nil)
let pso = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "burn")!)
let q = dev.makeCommandQueue()!
let a = CommandLine.arguments
let secs = Double(a[1])!, n = Int(a[2])!, bufMs = Double(a[3])!, duty = Double(a[4])!
let buf = dev.makeBuffer(length: n * 4)!
func run(_ iters: Int) -> Double {
  var it = Int32(iters)
  let cb = q.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
  e.setComputePipelineState(pso); e.setBuffer(buf, offset: 0, index: 0); e.setBytes(&it, length: 4, index: 1)
  e.dispatchThreads(MTLSize(width: n, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 256, height: 1, depth: 1))
  e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
  return cb.gpuEndTime - cb.gpuStartTime
}
// calibrate iterations to the target buffer length
var iters = 200
for _ in 0..<3 { let t = run(iters); iters = max(1, Int(Double(iters) * bufMs / 1000 / t)) }
print("pid", getpid(), "iters", iters); fflush(stdout)
sleep(2)
var gpu = 0.0, bufs = 0
let t0 = Date()
while Date().timeIntervalSince(t0) < secs {
  let t = run(iters); gpu += t; bufs += 1
  if duty < 1 { usleep(UInt32(t * (1 - duty) / duty * 1e6)) }
}
print("wall", Date().timeIntervalSince(t0), "metal_gpu_s", gpu, "buffers", bufs, "ms/buf", gpu / Double(bufs) * 1000); fflush(stdout)
sleep(1)
