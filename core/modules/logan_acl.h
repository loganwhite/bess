// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_MODULES_MYACL_H_
#define BESS_MODULES_MYACL_H_

#include <vector>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/ip.h"

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ipv4Prefix;

class MyACL final : public Module {
 public:
  struct ACLRule {
    bool Match(be32_t sip, be32_t dip, be16_t sport, be16_t dport) const {
      return src_ip.Match(sip) && dst_ip.Match(dip) &&
             (src_port == be16_t(0) || src_port == sport) &&
             (dst_port == be16_t(0) || dst_port == dport);
    }

    Ipv4Prefix src_ip;
    Ipv4Prefix dst_ip;
    be16_t src_port;
    be16_t dst_port;
    bool drop;
  };

  static const Commands cmds;

  MyACL() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  ~MyACL() { free(fake_state_); }
  

  CommandResponse Init(const bess::pb::MyACLArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::MyACLArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

 private:
  std::vector<ACLRule> rules_;
  
  size_t state_size_ = 0;
  uint8_t* fake_state_ = NULL;
  int shm_id_ = 0;   // the shared memory descriptor
  key_t shm_key_ = (key_t)1234;
  void* shm_;
  int InitShm();
  template<typename T>
  int FetchState(T** state);
  template<typename T>
  int SaveState(T** state, size_t size);
};

#endif  // BESS_MODULES_MYACL_H_
