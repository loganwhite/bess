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

#include "logan_acl.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"

const Commands MyACL::cmds = {
    {"add", "ACLArg", MODULE_CMD_FUNC(&MyACL::CommandAdd),
     Command::THREAD_UNSAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&MyACL::CommandClear),
     Command::THREAD_UNSAFE}};

CommandResponse MyACL::Init(const bess::pb::MyACLArg &arg) {
  state_size_ = (size_t)arg.state_size();
  fake_state_ = (uint8_t*)malloc(state_size_ * sizeof(uint8_t));

  //init redis connection
  InitRedisConnection();
  for (const auto &rule : arg.rules()) {
    ACLRule new_rule = {
        .src_ip = Ipv4Prefix(rule.src_ip()),
        .dst_ip = Ipv4Prefix(rule.dst_ip()),
        .src_port = be16_t(static_cast<uint16_t>(rule.src_port())),
        .dst_port = be16_t(static_cast<uint16_t>(rule.dst_port())),
        .drop = rule.drop()};
    rules_.push_back(new_rule);
  }
  
  SaveState<uint8_t>(&fake_state_, sizeof(uint8_t) * state_size_);

  return CommandSuccess();
}

CommandResponse MyACL::CommandAdd(const bess::pb::MyACLArg &arg) {
  fprintf(stderr,"enter command add...\n");
  Init(arg);
  return CommandSuccess();
}

CommandResponse MyACL::CommandClear(const bess::pb::EmptyArg &) {
  rules_.clear();
  return CommandSuccess();
}

void MyACL::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Udp;

  gate_idx_t incoming_gate = ctx->current_igate;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    size_t ip_bytes = ip->header_length << 2;
    Udp *udp =
        reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    bool emitted = false;
    if (rules_.size()) {
      // printf("Fetching from redis...\n");
      ACLRule new_rule = rules_.front();
      if (fake_state_) {
        free(fake_state_);
        fake_state_ = NULL;
      }
      FetchState<uint8_t>(&fake_state_);
      rules_.clear();
      rules_.push_back(new_rule);
    }

    for (const auto &rule : rules_) {
      if (rule.Match(ip->src, ip->dst, udp->src_port, udp->dst_port)) {
        if (!rule.drop) {
          emitted = true;
          EmitPacket(ctx, pkt, incoming_gate);
        }
        break;  // Stop matching other rules
      }
    }

    if (!emitted) {
      DropPacket(ctx, pkt);
    }
  }
}

template<typename T>
int MyACL::FetchState(T** state) {
  redisReply* reply = NULL;

  if (!is_connected_) return -1;
  // printf("start executing the redis commands...\n");
  reply = (redisReply*)redisCommand(context, "GET acl");
  if (!reply || reply->type == REDIS_REPLY_ERROR /* || !strcmp("(null)", reply->str) */) {
    fprintf(stderr, "Connot running redis commands or Redis server \
    returns an error. Error message: %s\n", reply ? reply->str : context->errstr);
    freeReplyObject(reply);
    return -1;
  }
  // printf("Redis: %s\n", reply->str);
  *state = (T*)malloc(sizeof(T) * state_size_);
  memcpy((*state), reply->str, state_size_ * sizeof(T));

  freeReplyObject(reply);
  return 0;
}


template<typename T>
int MyACL::SaveState(T** state, size_t size) {
  redisReply* reply = NULL;
  if (!is_connected_) return -1;
  printf("start executing the redis commands...\n");
  reply = (redisReply*)redisCommand(context, "SET acl %b", (*state), size);
  if (!reply || reply->type == REDIS_REPLY_ERROR || !strcmp("(null)", reply->str)) {
    fprintf(stderr, "Connot running redis commands or Redis \
    server returns an error. Error message: %s\n", reply ? reply->str : context->errstr);
    freeReplyObject(reply);
    return -1;
  }
  freeReplyObject(reply);
  return 0;
}

void MyACL::InitRedisConnection() {
  char err_msg[1024];
  strcat(err_msg, "Error message: ");
  printf("start connecting redis server...\n");
  context = redisConnect(REDIS_IP, REDIS_PORT);
  if (!context || context->err) {
    fprintf(stderr, "Cannot initialize or cannot connect \
    to the redis server. %s\n", context ? strcat(err_msg, context->errstr) : "");
    redisFree(context);
    return;
  }
  is_connected_ = true;
}


ADD_MODULE(MyACL, "myacl", "MyACL module from original MyACL")
