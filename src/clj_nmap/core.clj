;;   Copyright (c) 7theta. All rights reserved.
;;   The use and distribution terms for this software are covered by the
;;   Eclipse Public License 1.0 (http://www.eclipse.org/legal/epl-v10.html)
;;   which can be found in the LICENSE file at the root of this
;;   distribution.
;;
;;   By using this software in any fashion, you are agreeing to be bound by
;;   the terms of this license.
;;   You must not remove this notice, or any others, from this software.

(ns clj-nmap.core
  (:require [crusta.core :refer [run]]
            [utilis.types.number :refer [string->long string->double]]
            [utilis.map :refer [map-vals compact]]
            [clojure.data.xml :as xml]
            [clj-time.coerce :as tc]
            [clj-time.format :as tf]
            [clojure.set :refer [rename-keys]]))

(declare parse)

;;; Public

(defn nmap
  "Runs the nmap command the using 'opts' as command line parameters and returns
  the parsed output for a successful run.

  A exception is thrown if nmap terminates with a non-zero exit code.

  An optional ':debug true' keyword parameter can be passed at the end of the
  call to include the raw XML output from nmap in the response under [:debug :xml]"
  [& opts]
  (let [[fn-options nmap-options] (->> opts reverse (partition-all 2)
                                       (map reverse)
                                       (split-with #(keyword? (first %))))
        nmap-options (->> nmap-options reverse (reduce concat))
        fn-options (->> fn-options (map vec) (into {}))
        parse-ts (fn [ts] (-> ts string->long (* 1000) tc/from-long))
        raw-output @(run (into ["nmap" "-oX" "-"] nmap-options))
        output (xml/parse-str raw-output)
        [hosts extra] ((juxt filter remove) #(= :host (:tag %)) (:content output))
        stats (->> extra (filter #(= :runstats (:tag %)))
                   first :content
                   (map #(hash-map (:tag %) (:attrs %)))
                   (reduce merge))]
    (cond-> {:scan {:cmd (-> output :attrs :args)
                    :version (-> output :attrs :version)
                    :start (-> output :attrs :start
                               parse-ts)
                    :end (-> stats :finished :time
                             parse-ts)
                    :elapsed (-> stats :finished :elapsed
                                 string->double)
                    :count (map-vals string->long (:hosts stats))}
             :hosts (mapv (comp compact parse) hosts)}
      (:debug fn-options) (assoc :debug {:xml raw-output
                                         :ast output}))))

;;; Implementation

(defmulti ^:private parse :tag)

(defmethod ^:private parse :host
  [h]
  (->> h :content
       (map #(case (:tag %)
               :status {:status (rename-keys
                                 (map-vals keyword (:attrs %))
                                 {:reason_ttl :reason-ttl})}
               :address {:addresses [(let [addr (update (:attrs %) :addrtype keyword)]
                                       (rename-keys addr {:addr (:addrtype addr)
                                                          :addrtype :type}))]}
               :hostnames {:hostnames (map :attrs (:content %))}
               :ports {:ports (->> % :content (filter (fn [p] (= :port (:tag p))))
                                   (map parse))}
               :os (parse %)
               nil))
       (reduce (partial merge-with
                  (fn [a b] (if (and (seq a) (seq b)) (concat a b) b))))))

(defmethod ^:private parse :port
  [p]
  (-> (->> p :content
           (map parse)
           (reduce merge {:port (-> p :attrs :portid string->long)
                          :protocol (-> p :attrs :protocol keyword)}))
      (rename-keys {:state :status})
      (update :status (partial map-vals keyword))
      (update :status rename-keys {:reason_ttl :reason-ttl})))

(defmethod ^:private parse :service
  [s]
  {:service (cond-> (rename-keys (:attrs s)
                                 {:devicetype :device-type
                                  :servicefp :fingerprint})
              (not-empty (:content s)) (assoc :fingerprint
                                              (-> s :content first :content first)))})

(defmethod ^:private parse :script
  [s]
  (condp = (-> s :attrs :id)
    "ssl-cert" (parse (assoc s :tag :ssl-cert))
    {(-> s :attrs :id keyword) (->> s :content (map parse) (reduce merge))}))

(defmethod ^:private parse :ssl-cert
  [s]
  (let [owner (fn [a]
                (rename-keys (->> a :content
                                  (map #(array-map (-> % :attrs :key)
                                                   (-> % :content first)))
                                  (reduce merge))
                             {"commonName" :common-name
                              "countryName" :country-name}))
        validity (fn [a]
                   (rename-keys (->> a :content
                                     (map #(array-map (-> % :attrs :key)
                                                      (-> % :content first tf/parse)))
                                     (reduce merge))
                                {"notBefore" :not-before
                                 "notAfter" :not-after}))]
    {:ssl-cert (->> s :content
                    (map (fn [a]
                           (condp = (-> a :attrs :key)
                             "subject" {:subject (owner a)}
                             "issuer" {:issuer (owner a)}
                             "pubkey" {:public-key (reduce merge (map parse (:content a)))}
                             "sig_algo" {:signature-algorithm (-> a :content first)}
                             "validity" {:validity (validity a)}
                             (parse a))))
                    (reduce merge))}))

(defmethod ^:private parse :os
  [os]
  (let [match (->> os :content (filter #(= :osmatch (:tag %))) first)]
    {:os (merge (dissoc (:attrs match) :line)
                {:os-class (rename-keys
                            (->> match :content (filter #(= :osclass (:tag %)))
                                 first :attrs)
                            {:osfamily :os-family
                             :osgen :os-gen})}
                {:ports-used (->> os :content (filter #(= :portused (:tag %)))
                                  (map parse) (mapcat vals)
                                  (map #(-> %
                                            (rename-keys {:proto :protocol
                                                          :portid :port-id})
                                            (update :state keyword)
                                            (update :protocol keyword)
                                            (update :port-id string->long))))})}))

(defmethod ^:private parse :table
  [e]
  (let [key (-> e :attrs :key keyword)]
    (cond->> (->> e :content (map parse) (reduce merge))
      key (array-map key))))

(defmethod ^:private parse :elem
  [e]
  {(-> e :attrs :key keyword) (-> e :content first)})

(defmethod ^:private parse :default
  [v]
  {(:tag v) (:attrs v)})
