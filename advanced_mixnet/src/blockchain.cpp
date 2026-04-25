/**
 * @file blockchain.cpp
 * @brief Implémentation de la Blockchain Mixnet
 */

#include "blockchain.h"
#include "crypto_utils.h"
#include <algorithm>
#include <iostream>
#include <thread>

namespace mixnet {
namespace blockchain {

// ============================================================================
// Block Implementation
// ============================================================================

Block::Block() 
    : index(0), timestamp(0), nonce(0) {}

Block::Block(uint64_t idx, const std::string& prev_hash)
    : index(idx), timestamp(utils::get_timestamp_ms()), 
      previous_hash(prev_hash), nonce(0) {}

std::string Block::calculate_hash() const {
    std::stringstream ss;
    ss << index << timestamp << message_hash << sender << receiver 
       << message_content << previous_hash << nonce;
    return utils::SHA256::hash_hex(ss.str());
}

bool Block::verify_hash(size_t difficulty) const {
    return utils::HexEncoder::decode(current_hash).size() > 0 &&
           current_hash.substr(0, difficulty) == std::string(difficulty, '0');
}

void Block::mine(size_t difficulty) {
    std::string prefix(difficulty, '0');
    do {
        nonce++;
        current_hash = calculate_hash();
    } while (current_hash.substr(0, difficulty) != prefix);
}

// ============================================================================
// PendingMessage Implementation
// ============================================================================

uint64_t MixnetBlockchain::PendingMessage::get_current_timestamp() {
    return utils::get_timestamp_ms();
}

// ============================================================================
// MixnetBlockchain Implementation
// ============================================================================

MixnetBlockchain::MixnetBlockchain(size_t difficulty)
    : difficulty_(difficulty), mining_active_(false), last_mine_time_(0) {}

void MixnetBlockchain::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!chain_.empty()) return;
    
    // Create genesis block
    Block genesis(0, "0");
    genesis.message_hash = "genesis";
    genesis.sender = "system";
    genesis.receiver = "system";
    genesis.message_content = "Genesis block - Mixnet initialized";
    genesis.timestamp = utils::get_timestamp_ms();
    genesis.mine(difficulty_);
    
    chain_.push_back(genesis);
    
    if (on_block_mined_) {
        on_block_mined_(genesis);
    }
}

void MixnetBlockchain::add_pending_message(const std::string& sender,
                                           const std::string& receiver,
                                           const std::string& content) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_messages_.emplace_back(sender, receiver, content);
}

size_t MixnetBlockchain::mine_pending() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (pending_messages_.empty()) return 0;
    
    size_t mined_count = 0;
    std::string prev_hash = chain_.empty() ? "0" : chain_.back().current_hash;
    
    for (const auto& msg : pending_messages_) {
        Block new_block(chain_.size(), prev_hash);
        new_block.sender = msg.sender;
        new_block.receiver = msg.receiver;
        new_block.message_content = msg.content;
        new_block.message_hash = utils::SHA256::hash_hex(msg.content);
        
        // Mine the block
        new_block.mine(difficulty_);
        
        // Verify before adding
        if (new_block.verify_hash(difficulty_)) {
            chain_.push_back(new_block);
            prev_hash = new_block.current_hash;
            mined_count++;
            
            if (on_block_mined_) {
                // Call callback outside lock in real implementation
            }
        }
    }
    
    pending_messages_.clear();
    last_mine_time_ = utils::get_timestamp_ms();
    
    return mined_count;
}

bool MixnetBlockchain::add_block(Block block) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (chain_.empty() && block.index != 0) {
        return false;
    }
    
    if (!chain_.empty() && block.previous_hash != chain_.back().current_hash) {
        return false;
    }
    
    if (!block.verify_hash(difficulty_)) {
        return false;
    }
    
    chain_.push_back(block);
    return true;
}

bool MixnetBlockchain::verify_chain() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (chain_.empty()) return false;
    
    // Verify genesis
    if (chain_[0].index != 0) return false;
    
    // Verify each block
    for (size_t i = 1; i < chain_.size(); ++i) {
        const auto& prev = chain_[i - 1];
        const auto& current = chain_[i];
        
        // Check link
        if (current.previous_hash != prev.current_hash) {
            return false;
        }
        
        // Check index
        if (current.index != i) {
            return false;
        }
        
        // Verify hash meets difficulty
        if (!current.verify_hash(difficulty_)) {
            return false;
        }
        
        // Verify hash is correct
        if (current.current_hash != current.calculate_hash()) {
            return false;
        }
    }
    
    return true;
}

size_t MixnetBlockchain::get_chain_length() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chain_.size();
}

const Block* MixnetBlockchain::get_latest_block() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (chain_.empty()) return nullptr;
    return &chain_.back();
}

const Block* MixnetBlockchain::get_block(size_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= chain_.size()) return nullptr;
    return &chain_[index];
}

MixnetBlockchain::BlockchainStatus MixnetBlockchain::get_status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    BlockchainStatus status;
    status.chain_length = chain_.size();
    status.pending_count = pending_messages_.size();
    status.difficulty = difficulty_;
    status.last_mine_time = last_mine_time_.load();
    status.is_mining = mining_active_.load();
    
    return status;
}

void MixnetBlockchain::set_difficulty(size_t difficulty) {
    std::lock_guard<std::mutex> lock(mutex_);
    difficulty_ = difficulty;
}

size_t MixnetBlockchain::get_difficulty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return difficulty_;
}

void MixnetBlockchain::set_on_block_mined(OnBlockMinedCallback callback) {
    on_block_mined_ = callback;
}

void MixnetBlockchain::start_mining_loop() {
    mining_active_ = true;
    
    std::thread([this]() {
        while (mining_active_) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            if (mining_active_) {
                size_t mined = mine_pending();
                if (mined > 0 && on_block_mined_) {
                    // Notify callbacks
                }
            }
        }
    }).detach();
}

void MixnetBlockchain::stop_mining_loop() {
    mining_active_ = false;
}

std::string MixnetBlockchain::sha256(const std::string& input) {
    return utils::SHA256::hash_hex(input);
}

bool MixnetBlockchain::hash_meets_difficulty(const std::string& hash, size_t difficulty) {
    if (hash.length() < difficulty) return false;
    return hash.substr(0, difficulty) == std::string(difficulty, '0');
}

} // namespace blockchain
} // namespace mixnet
