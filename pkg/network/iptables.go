package network

const (
	jumpTarget string = "NFQUEUE"
)

// InsertNFQueueRule insert NFQueue rule in the specified chain as the given rule number
func InsertNFQueueRule(chainName string, ruleNum uint, protocol string, queueNum uint16) error

// DeleteNFQueueRule delete NFQueue rule in the specified chain as the given rule number
func DeleteNFQueueRule(chainName string, ruleNum uint, protocol string, queueNum uint16) error
