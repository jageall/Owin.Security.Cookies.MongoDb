﻿/*
 * Copyright 2014, 2015 James Geall
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
using System;

namespace Owin.Security.Cookies.MongoDB
{
    public class MongoAuthenticationSessionStoreOptions
    {
        public MongoAuthenticationSessionStoreOptions()
        {
            ConnectionString = "mongodb://localhost";
            Database = "AuthenticationSessionStore";
            Collection = "AuthenticationTickets";
            DefaultExpiry = TimeSpan.FromHours(1);
            Clock = () => DateTimeOffset.UtcNow;
        }

        public string ConnectionString { get; set; }

        public string Database { get; set; }

        public string Collection { get; set; }

        public TimeSpan DefaultExpiry { get; set; }

        public Func<DateTimeOffset> Clock { get; set; }
    }
}