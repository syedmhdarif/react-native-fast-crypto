module.exports = {
  preset: 'react-native',
  testMatch: ['**/__tests__/unit/**/*.test.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],
  transform: {
    '^.+\\.(ts|tsx)$': [
      'babel-jest',
      { presets: ['@react-native/babel-preset'] },
    ],
  },
  transformIgnorePatterns: ['node_modules/(?!(react-native|@react-native)/)'],
};
