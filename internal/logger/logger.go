// Copyright 2021 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"fmt"

	"github.com/globalsign/est"
	"go.uber.org/zap"
)

// ZapWrappingLogger is a logger conforming to est.Logger
// that wraps a *zap.Logger instance
type ZapWrappingLogger struct {
	*zap.Logger
}

// Errorf uses fmt.Sprintf to log a formatted message
func (l ZapWrappingLogger) Errorf(format string, v ...interface{}) {
	l.Error(fmt.Sprintf(format, v...))
}

// Errorw uses fmt.Sprintf to log an Error message with additional context
func (l ZapWrappingLogger) Errorw(msg string, keysAndValues ...interface{}) {
	fields := createZapFields(keysAndValues...)
	l.Error(msg, fields...)
}

// Infof uses fmt.Sprintf to log a formatted message
func (l ZapWrappingLogger) Infof(format string, v ...interface{}) {
	l.Info(fmt.Sprintf(format, v...))
}

// Infow uses fmt.Sprintf to log an Info message with additional context
func (l ZapWrappingLogger) Infow(msg string, keysAndValues ...interface{}) {
	fields := createZapFields(keysAndValues...)
	l.Info(msg, fields...)
}

// With adds a variadic number of key/value pairs to the logging context
// as zap.Field structs
func (l ZapWrappingLogger) With(keysAndValues ...interface{}) est.Logger {

	newLogger := ZapWrappingLogger{
		Logger: l.Logger,
	}

	fields := createZapFields(keysAndValues...)

	newLogger.Logger.With(fields...)

	return newLogger
}

// createZapFields processes create zap.Field structs from
// additional context passed as key/value pairs
func createZapFields(extra ...interface{}) []zap.Field {

	if len(extra)%2 != 0 {
		panic("number of arguments is not a multiple of 2")
	}

	fields := []zap.Field{}
	for i := 0; i < len(extra); i += 2 {
		key, ok := extra[i].(string)
		if !ok {
			panic(fmt.Sprintf("argument %d is not a string", i))
		}
		value := extra[i+1]

		fields = append(fields, zap.Reflect(key, value))
	}

	return fields
}
