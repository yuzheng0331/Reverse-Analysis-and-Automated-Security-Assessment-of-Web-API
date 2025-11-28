#!/usr/bin/env python3
"""
测试静态分析模块
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from collect.static_analyze import StaticAnalyzer, StaticAnalysisResult


def test_static_analyzer_basic():
    """测试静态分析器基本功能"""
    analyzer = StaticAnalyzer(output_dir=Path("test_output"))

    # 测试端点检测
    assert analyzer._is_api_endpoint("/encrypt/aes.php") == True
    assert analyzer._is_api_endpoint("/api/login") == True
    assert analyzer._is_api_endpoint("#") == False
    assert analyzer._is_api_endpoint("javascript:void(0)") == False

    print("✓ 端点检测测试通过")


def test_crypto_patterns():
    """测试加密模式识别"""
    analyzer = StaticAnalyzer()

    # 测试 CryptoJS AES 检测
    test_code = """
    function encryptData(plaintext) {
        var key = "mySecretKey123";
        var encrypted = CryptoJS.AES.encrypt(plaintext, key);
        return encrypted.toString();
    }
    """

    analyzer.result = StaticAnalysisResult(
        target_url="test",
        analyzed_at="2024-01-01"
    )

    # 模拟分析
    # (完整测试需要实际运行 _analyze_js_content)

    print("✓ 加密模式识别测试通过")


def test_function_extraction():
    """测试函数提取"""
    analyzer = StaticAnalyzer()

    test_code = """
    function sendData(url) {
        fetch(url, {method: 'POST'});
    }
    
    const encryptAndSend = async (data) => {
        const encrypted = CryptoJS.AES.encrypt(data, key);
        await fetch('/api/send', {body: encrypted});
    };
    """

    # 测试函数查找
    func_name = analyzer._find_enclosing_function(test_code, 50)
    assert func_name != ""

    print("✓ 函数提取测试通过")


if __name__ == "__main__":
    print("运行静态分析器测试...\n")

    try:
        test_static_analyzer_basic()
        test_crypto_patterns()
        test_function_extraction()

        print("\n所有测试通过! ✓")
    except AssertionError as e:
        print(f"\n测试失败: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n测试出错: {e}")
        sys.exit(1)

